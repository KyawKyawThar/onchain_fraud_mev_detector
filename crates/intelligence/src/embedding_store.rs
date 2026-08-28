//! The ClickHouse behavior-embedding store (§20.3, §14): append-only
//! per-address behavior vectors, keyed by `(chain, address, embedding_version)`
//! and read back latest-first.
//!
//! **`ReplacingMergeTree`, deliberately unlike its append-only neighbours.**
//! [`crate::production_store`] is append-only because a block-production record
//! legitimately *evolves* — incidents fold in, retractions subtract, reorgs
//! revert — so every snapshot is part of the story. A recomputed behavior
//! vector instead fully *supersedes* its predecessor, and nothing reads the
//! history: similarity search and the clustering signal both want latest-only.
//! Keeping every hourly recomputation of every address forever would grow the
//! table as address-space x time rather than address-space, for data no
//! consumer reads. Consistency with a neighbouring table is not a reason when
//! the underlying write semantics differ.
//!
//! Reads still take the latest *explicitly* (`ORDER BY computed_at DESC LIMIT 1`)
//! rather than assuming the engine has merged: `ReplacingMergeTree`
//! deduplicates eventually, not immediately, and a read that assumed otherwise
//! would intermittently serve a superseded vector.
//!
//! `embedding_version` and `schema_hash` are part of the row's identity rather
//! than metadata beside it: two vectors are only comparable if both match, so
//! every read filters on the version and carries the hash back for the caller
//! to check (see [`StoredEmbedding::matches`]).

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clickhouse::Client;
use events::intelligence::BehaviorFactor;
use events::primitives::{AccountAddress, Chain, EntityId};
use serde::{Deserialize, Serialize};

use crate::embedding::baseline::BehaviorBaseline;
use crate::embedding::BehaviorVector;
use crate::model::{address_key, parse_address_key, AddressKeyError};

/// A failure writing or reading behavior vectors. ClickHouse faults are I/O —
/// always transient (an append is idempotent-by-convergence: the same inputs
/// recompute to the same vector, so a retried write is a duplicate row the
/// latest-per-key read collapses). A stored row that no longer decodes is
/// permanent for that row.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddingStoreError {
    #[error("clickhouse round-trip failed")]
    Clickhouse(#[from] clickhouse::error::Error),

    /// A stored value no longer parses — a corrupt row, or one written by a
    /// build whose encoding this one doesn't understand. Retrying re-reads the
    /// same bytes.
    #[error("stored value is malformed: {what}")]
    Malformed { what: String },
}

impl From<AddressKeyError> for EmbeddingStoreError {
    fn from(err: AddressKeyError) -> Self {
        EmbeddingStoreError::Malformed {
            what: err.to_string(),
        }
    }
}

impl event_bus::Transience for EmbeddingStoreError {
    /// Whether retrying could plausibly succeed — the shared retry/skip
    /// contract.
    fn is_transient(&self) -> bool {
        matches!(self, EmbeddingStoreError::Clickhouse(_))
    }
}

/// One vector read back out of the store, with everything needed to decide
/// whether it may be compared to another.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEmbedding {
    pub address: AccountAddress,
    pub entity_id: Option<EntityId>,
    pub embedding_version: String,
    pub schema_hash: String,
    pub values: Vec<f32>,
    pub top_factors: Vec<BehaviorFactor>,
    pub observations_truncated: bool,
    pub computed_at: DateTime<Utc>,
}

impl StoredEmbedding {
    /// Whether this vector was produced by the given schema — the guard a
    /// comparison must pass. Version *and* hash: a matching version with a
    /// different hash is precisely the accident (an edit to a frozen schema)
    /// that a version string alone cannot catch.
    pub fn matches(&self, embedding_version: &str, schema_hash: &str) -> bool {
        self.embedding_version == embedding_version && self.schema_hash == schema_hash
    }

    /// The same content digest a freshly computed
    /// [`BehaviorVector`](crate::embedding::BehaviorVector) produces — the
    /// change-detection comparison
    /// [`decide_write`](crate::embedding_job::decide_write) makes on every
    /// page. Shares one function with the compute side by construction, so the
    /// two cannot drift into "everything always looks changed".
    pub fn content_digest(&self) -> u64 {
        crate::embedding::content_digest(
            &self.address,
            &self.embedding_version,
            &self.schema_hash,
            self.observations_truncated,
            &self.values,
        )
    }
}

/// The behavior-embedding store seam. Object-safe; production is
/// [`ClickhouseEmbeddingStore`], tests use the recording double in
/// [`crate::test_util`].
#[async_trait]
pub trait EmbeddingStore: Send + Sync {
    /// Append computed vectors (immutable; a recomputation that lands on the
    /// same values is a harmless extra row the latest-per-key read collapses).
    async fn append(
        &self,
        chain: Chain,
        vectors: &[BehaviorVector],
    ) -> Result<(), EmbeddingStoreError>;

    /// The most recent vector for `(chain, address, embedding_version)`, or
    /// `None` if this address has never been embedded under that version.
    async fn latest(
        &self,
        chain: Chain,
        address: &AccountAddress,
        embedding_version: &str,
    ) -> Result<Option<StoredEmbedding>, EmbeddingStoreError>;

    /// The latest vector for *many* addresses at once — the batched form of
    /// [`Self::latest`]. Returns an entry only for addresses that have one.
    ///
    /// The sweep uses this to decide, for a whole page, which recomputations
    /// actually changed anything; one query per address there would be a
    /// round trip per address purely to *avoid* work, which is worse than the
    /// work. The default loops [`Self::latest`] so a double stays correct for
    /// free; the ClickHouse impl overrides it with one `LIMIT 1 BY address`.
    async fn latest_many(
        &self,
        chain: Chain,
        addresses: &[AccountAddress],
        embedding_version: &str,
    ) -> Result<HashMap<AccountAddress, StoredEmbedding>, EmbeddingStoreError> {
        let mut out = HashMap::with_capacity(addresses.len());
        for address in addresses {
            if let Some(found) = self.latest(chain, address, embedding_version).await? {
                out.insert(*address, found);
            }
        }
        Ok(out)
    }

    /// The `limit` rows whose stored vector is closest to `query` in **raw**
    /// cosine distance — the candidate-generation half of a similarity search
    /// (§20.3, see [`crate::similarity`]).
    ///
    /// Deliberately *not* the final ranking. Comparison in this subsystem is
    /// standardized against a population baseline, and standardization is an
    /// affine shift no vector index can express, so this shortlist is scored
    /// in the wrong space on purpose and re-ranked exactly by the caller. Over-
    /// fetching is what buys the recall back.
    ///
    /// Excludes `exclude` (the subject) in SQL rather than over-fetching by one
    /// and dropping it, and returns rows straight off the table — including a
    /// superseded row a `ReplacingMergeTree` has not merged away yet, which the
    /// caller collapses. See the impl for why the latest-per-address `LIMIT 1
    /// BY` the other reads use is deliberately absent here.
    async fn nearest_candidates(
        &self,
        chain: Chain,
        embedding_version: &str,
        query: &[f32],
        exclude: &AccountAddress,
        limit: usize,
    ) -> Result<Vec<StoredEmbedding>, EmbeddingStoreError>;

    /// A previously materialized neighbour ranking for `address`, if one
    /// exists — the [`address_neighbors`] read model (§20.3).
    ///
    /// Returns whatever is stored, **including a stale one**: validating the
    /// `baseline_fingerprint` is the caller's job, because only the caller
    /// knows which baseline is current. A store that silently dropped
    /// mismatched rows would hide the invalidation from the metric that counts
    /// it.
    async fn cached_neighbors(
        &self,
        chain: Chain,
        address: &AccountAddress,
        embedding_version: &str,
    ) -> Result<Option<CachedNeighbors>, EmbeddingStoreError>;

    /// Materialize a neighbour ranking. Idempotent by convergence — the same
    /// inputs recompute to the same ranking, so a retried write is a duplicate
    /// row the latest-per-key read collapses.
    async fn put_neighbors(
        &self,
        chain: Chain,
        entry: &CachedNeighbors,
    ) -> Result<(), EmbeddingStoreError>;

    /// A bounded, deterministic sample of latest-per-address vectors — the
    /// input to [`baseline::compute`](crate::embedding::baseline::compute).
    ///
    /// Sampled rather than swept: a population median does not get materially
    /// better past a few tens of thousands of addresses, and reading the whole
    /// table to compute one would be the most expensive query this service
    /// issues. The sample is deterministic for a given `(chain, version,
    /// limit)` so a re-derived baseline is reproducible.
    async fn sample_vectors(
        &self,
        chain: Chain,
        embedding_version: &str,
        limit: u32,
    ) -> Result<Vec<Vec<f32>>, EmbeddingStoreError>;

    /// Store a freshly computed population baseline.
    async fn put_baseline(
        &self,
        chain: Chain,
        baseline: &BehaviorBaseline,
    ) -> Result<(), EmbeddingStoreError>;

    /// The most recent baseline for `(chain, embedding_version)`, or `None`
    /// when none has been computed yet — a miss, never a synthesized identity
    /// baseline, which would silently rank against unstandardized units.
    async fn latest_baseline(
        &self,
        chain: Chain,
        embedding_version: &str,
    ) -> Result<Option<BehaviorBaseline>, EmbeddingStoreError>;
}

/// One stored row. Field order mirrors the `address_embeddings` columns;
/// `appended_at` is intentionally absent (ClickHouse fills its `DEFAULT`).
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct EmbeddingRow {
    pub chain: u64,
    pub address: String,
    pub embedding_version: String,
    pub schema_hash: String,
    /// `''` when the address belongs to no entity — the same flatten-an-Option
    /// convention as `block_production`'s absent relay/label.
    pub entity_id: String,
    pub vector: Vec<f32>,
    /// JSON array of `{feature, value, share}` objects.
    pub top_factors: String,
    pub observations_truncated: u8,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub computed_at: DateTime<Utc>,
}

impl EmbeddingRow {
    /// Total mapping from the computed vector — nothing here can fail (the
    /// factors are plain structs, so their serialization is total).
    pub fn from_vector(chain: Chain, vector: &BehaviorVector) -> Self {
        Self {
            chain: chain.id(),
            address: address_key(&vector.address),
            embedding_version: vector.embedding_version().to_owned(),
            schema_hash: vector.schema_hash().to_owned(),
            entity_id: vector
                .entity_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            vector: vector.values.clone(),
            top_factors: serde_json::to_string(
                &vector.top_factors(crate::embedding::MAX_VISIBLE_FACTORS),
            )
            .expect("Vec<BehaviorFactor> serialization is total"),
            observations_truncated: u8::from(vector.observations_truncated),
            computed_at: vector.computed_at,
        }
    }
}

impl TryFrom<EmbeddingRow> for StoredEmbedding {
    type Error = EmbeddingStoreError;

    /// Fallible in exactly the ways a stored row can be corrupt: an address or
    /// entity id that no longer parses, and a factors blob that no longer
    /// decodes.
    fn try_from(row: EmbeddingRow) -> Result<Self, EmbeddingStoreError> {
        let entity_id = match row.entity_id.as_str() {
            "" => None,
            raw => Some(EntityId(raw.parse().map_err(|_| {
                EmbeddingStoreError::Malformed {
                    what: format!("entity id {raw:?} is not a UUID"),
                }
            })?)),
        };
        let top_factors: Vec<BehaviorFactor> =
            serde_json::from_str(&row.top_factors).map_err(|err| {
                EmbeddingStoreError::Malformed {
                    what: format!("stored top_factors did not decode: {err}"),
                }
            })?;
        Ok(StoredEmbedding {
            address: parse_address_key(&row.address)?,
            entity_id,
            embedding_version: row.embedding_version,
            schema_hash: row.schema_hash,
            values: row.vector,
            top_factors,
            observations_truncated: row.observations_truncated != 0,
            computed_at: row.computed_at,
        })
    }
}

/// One stored baseline row.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct BaselineRow {
    pub chain: u64,
    pub embedding_version: String,
    pub schema_hash: String,
    pub centre: Vec<f32>,
    pub spread: Vec<f32>,
    pub sample_count: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub computed_at: DateTime<Utc>,
}

impl BaselineRow {
    /// Total mapping from the computed baseline — nothing here can fail.
    pub fn from_baseline(chain: Chain, baseline: &BehaviorBaseline) -> Self {
        Self {
            chain: chain.id(),
            embedding_version: baseline.embedding_version.clone(),
            schema_hash: baseline.schema_hash.clone(),
            centre: baseline.centre.clone(),
            spread: baseline.spread.clone(),
            sample_count: baseline.sample_count,
            computed_at: baseline.computed_at,
        }
    }
}

impl From<BaselineRow> for BehaviorBaseline {
    /// Infallible: every column is a plain value, so unlike an embedding row
    /// there is nothing here that can fail to parse.
    fn from(row: BaselineRow) -> Self {
        BehaviorBaseline {
            embedding_version: row.embedding_version,
            schema_hash: row.schema_hash,
            centre: row.centre,
            spread: row.spread,
            sample_count: row.sample_count,
            computed_at: row.computed_at,
        }
    }
}

/// One materialized neighbour ranking, with the baseline identity that makes
/// it safe (or unsafe) to reuse.
#[derive(Debug, Clone, PartialEq)]
pub struct CachedNeighbors {
    pub address: AccountAddress,
    pub embedding_version: String,
    /// The [`BehaviorBaseline::fingerprint`] this ranking was produced under.
    /// A read whose current baseline differs must discard the entry.
    pub baseline_fingerprint: String,
    /// Most similar first — already ranked, already truncated.
    pub neighbors: Vec<CachedNeighbor>,
    /// The `approximate` flag the live search reported, carried through so a
    /// cached answer states the same fidelity an uncached one would.
    pub approximate: bool,
    pub computed_at: DateTime<Utc>,
}

/// One neighbour inside a materialized ranking.
#[derive(Debug, Clone, PartialEq)]
pub struct CachedNeighbor {
    pub address: AccountAddress,
    pub entity_id: Option<EntityId>,
    pub similarity: f32,
    /// The per-feature explanation, exactly as the live path produced it.
    pub factors: Vec<events::intelligence::BehaviorFactor>,
}

/// One `address_neighbors` row. Parallel arrays because the ranking is read
/// and written whole and never queried into.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct NeighborsRow {
    pub chain: u64,
    pub address: String,
    pub embedding_version: String,
    pub baseline_fingerprint: String,
    pub neighbor_address: Vec<String>,
    pub neighbor_similarity: Vec<f32>,
    pub neighbor_entity_id: Vec<String>,
    pub neighbor_factors: Vec<String>,
    pub approximate: u8,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub computed_at: DateTime<Utc>,
}

impl NeighborsRow {
    /// Total mapping from the domain form.
    pub fn from_entry(chain: Chain, entry: &CachedNeighbors) -> Self {
        Self {
            chain: chain.id(),
            address: address_key(&entry.address),
            embedding_version: entry.embedding_version.clone(),
            baseline_fingerprint: entry.baseline_fingerprint.clone(),
            neighbor_address: entry
                .neighbors
                .iter()
                .map(|n| address_key(&n.address))
                .collect(),
            neighbor_similarity: entry.neighbors.iter().map(|n| n.similarity).collect(),
            neighbor_entity_id: entry
                .neighbors
                .iter()
                .map(|n| n.entity_id.map(|id| id.to_string()).unwrap_or_default())
                .collect(),
            neighbor_factors: entry
                .neighbors
                .iter()
                .map(|n| {
                    serde_json::to_string(&n.factors)
                        .expect("Vec<BehaviorFactor> serialization is total")
                })
                .collect(),
            approximate: u8::from(entry.approximate),
            computed_at: entry.computed_at,
        }
    }
}

impl TryFrom<NeighborsRow> for CachedNeighbors {
    type Error = EmbeddingStoreError;

    /// Fallible where a stored row can be corrupt — and **ragged arrays are a
    /// corruption, not a shrug**. The four parallel arrays are equal-length by
    /// construction; if they are not, zipping them would silently pair one
    /// neighbour's address with another's score.
    fn try_from(row: NeighborsRow) -> Result<Self, EmbeddingStoreError> {
        let n = row.neighbor_address.len();
        if row.neighbor_similarity.len() != n
            || row.neighbor_entity_id.len() != n
            || row.neighbor_factors.len() != n
        {
            return Err(EmbeddingStoreError::Malformed {
                what: format!(
                    "ragged neighbour arrays: {n} addresses, {} similarities, \
                     {} entity ids, {} factor blobs",
                    row.neighbor_similarity.len(),
                    row.neighbor_entity_id.len(),
                    row.neighbor_factors.len(),
                ),
            });
        }

        let mut neighbors = Vec::with_capacity(n);
        for index in 0..n {
            let entity_id = match row.neighbor_entity_id[index].as_str() {
                "" => None,
                raw => Some(EntityId(raw.parse().map_err(|_| {
                    EmbeddingStoreError::Malformed {
                        what: format!("entity id {raw:?} is not a UUID"),
                    }
                })?)),
            };
            neighbors.push(CachedNeighbor {
                address: parse_address_key(&row.neighbor_address[index])?,
                entity_id,
                similarity: row.neighbor_similarity[index],
                factors: serde_json::from_str(&row.neighbor_factors[index]).map_err(|err| {
                    EmbeddingStoreError::Malformed {
                        what: format!("stored neighbour factors did not decode: {err}"),
                    }
                })?,
            });
        }

        Ok(CachedNeighbors {
            address: parse_address_key(&row.address)?,
            embedding_version: row.embedding_version,
            baseline_fingerprint: row.baseline_fingerprint,
            neighbors,
            approximate: row.approximate != 0,
            computed_at: row.computed_at,
        })
    }
}

/// The **candidate shortlist's** row shape — a deliberately narrower
/// projection than [`EmbeddingRow`], and a different read model rather than a
/// convenience.
///
/// `top_factors` is the column that matters by its absence. It is a JSON blob
/// of the vector's own stored explanation, and the shortlist has no use for
/// it: a similarity search explains a *pair*, deriving its factors from
/// `values` against the subject, so the stored single-address explanation is
/// parsed and dropped. At the default shortlist cap that is on the order of a
/// megabyte of `serde_json` per request spent to produce nothing.
///
/// This is why the query names its columns instead of using `?fields`, which
/// expands to the whole row and silently re-couples the shortlist to every
/// column the write side happens to add later.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct CandidateRow {
    pub address: String,
    pub embedding_version: String,
    pub schema_hash: String,
    pub entity_id: String,
    pub vector: Vec<f32>,
    pub observations_truncated: u8,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub computed_at: DateTime<Utc>,
}

/// The column list [`CandidateRow`] decodes, in declaration order.
///
/// Kept beside the struct because the two must agree: ClickHouse returns
/// columns positionally in `RowBinary`, so a field added here without a
/// matching column name (or in a different order) decodes garbage rather than
/// failing loudly. `candidate_projection_matches_the_row_struct` pins it.
const CANDIDATE_COLUMNS: &str =
    "address, embedding_version, schema_hash, entity_id, vector, observations_truncated, computed_at";

impl TryFrom<CandidateRow> for StoredEmbedding {
    type Error = EmbeddingStoreError;

    /// Fallible in the same ways [`EmbeddingRow`]'s conversion is, minus the
    /// factors blob this projection never reads. `top_factors` lands empty:
    /// the shortlist's consumer computes a pairwise explanation and never
    /// looks at the stored single-address one.
    fn try_from(row: CandidateRow) -> Result<Self, EmbeddingStoreError> {
        let entity_id = match row.entity_id.as_str() {
            "" => None,
            raw => Some(EntityId(raw.parse().map_err(|_| {
                EmbeddingStoreError::Malformed {
                    what: format!("entity id {raw:?} is not a UUID"),
                }
            })?)),
        };
        Ok(StoredEmbedding {
            address: parse_address_key(&row.address)?,
            entity_id,
            embedding_version: row.embedding_version,
            schema_hash: row.schema_hash,
            values: row.vector,
            top_factors: Vec::new(),
            observations_truncated: row.observations_truncated != 0,
            computed_at: row.computed_at,
        })
    }
}

/// Just the `vector` column — the baseline sample read's row shape.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct VectorOnlyRow {
    vector: Vec<f32>,
}

/// Render a query vector as a ClickHouse array literal whose elements are
/// unambiguously floats.
///
/// `Debug` rather than `Display` for a reason worth stating: `Display` prints
/// `1.0f32` as `1`, so a vector of whole numbers renders as `[1,0,1]`, which
/// ClickHouse types as `Array(UInt8)`. `cosineDistance` accepts that and
/// returns the right answer — while skipping the vector-similarity index
/// entirely. A silent, correct, slow query is the worst failure shape
/// available here, so the rendering that cannot produce it is the one used.
/// `Debug` emits either a decimal point or an exponent for every finite f32,
/// both of which ClickHouse types as a float.
///
/// A non-finite value is rejected rather than rendered: `inf`/`NaN` would make
/// every distance NaN and the resulting order arbitrary. No embedder can
/// produce one (§18's determinism contract), so this is a corrupt-row guard,
/// which is why it is a `Malformed` and not a panic.
fn vector_literal(values: &[f32]) -> Result<String, EmbeddingStoreError> {
    let mut out = String::with_capacity(values.len() * 8 + 2);
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if !value.is_finite() {
            return Err(EmbeddingStoreError::Malformed {
                what: format!("query vector element {index} is not finite ({value})"),
            });
        }
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!("{value:?}"));
    }
    out.push(']');
    Ok(out)
}

/// ClickHouse-backed [`EmbeddingStore`]. Cheap to clone (the client is
/// `Arc`-cheap).
#[derive(Clone)]
pub struct ClickhouseEmbeddingStore {
    client: Client,
}

impl ClickhouseEmbeddingStore {
    /// Wrap a ClickHouse client (see
    /// [`crate::adjacency::build_clickhouse_client`]).
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EmbeddingStore for ClickhouseEmbeddingStore {
    async fn append(
        &self,
        chain: Chain,
        vectors: &[BehaviorVector],
    ) -> Result<(), EmbeddingStoreError> {
        if vectors.is_empty() {
            return Ok(());
        }
        let mut insert = self
            .client
            .insert::<EmbeddingRow>("address_embeddings")
            .await?;
        for vector in vectors {
            insert
                .write(&EmbeddingRow::from_vector(chain, vector))
                .await?;
        }
        insert.end().await?;
        Ok(())
    }

    async fn latest(
        &self,
        chain: Chain,
        address: &AccountAddress,
        embedding_version: &str,
    ) -> Result<Option<StoredEmbedding>, EmbeddingStoreError> {
        // Latest-per-key by `computed_at`, served straight off the table's
        // ORDER BY prefix — no argMax fan-out needed for a single-address
        // read, unlike the leaderboard's cross-block aggregate.
        let row: Option<EmbeddingRow> = self
            .client
            .query(
                "SELECT ?fields FROM address_embeddings \
                 WHERE chain = ? AND address = ? AND embedding_version = ? \
                 ORDER BY computed_at DESC LIMIT 1",
            )
            .bind(chain.id())
            .bind(address_key(address))
            .bind(embedding_version)
            .fetch_optional()
            .await?;

        row.map(StoredEmbedding::try_from).transpose()
    }

    async fn latest_many(
        &self,
        chain: Chain,
        addresses: &[AccountAddress],
        embedding_version: &str,
    ) -> Result<HashMap<AccountAddress, StoredEmbedding>, EmbeddingStoreError> {
        if addresses.is_empty() {
            return Ok(HashMap::new());
        }
        // The address list is our own canonical lowercase 0x-hex (never user
        // free-text), so inlining it as an `IN (...)` list is injection-safe —
        // the same stance `adjacency::neighbors_many` takes. `LIMIT 1 BY
        // address` after the ordering is the latest-per-address collapse,
        // done in one round trip instead of one per address.
        let keys: Vec<String> = addresses.iter().map(address_key).collect();
        let in_list = keys
            .iter()
            .map(|k| format!("'{k}'"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT ?fields FROM address_embeddings \
             WHERE chain = ? AND embedding_version = ? AND address IN ({in_list}) \
             ORDER BY address, computed_at DESC LIMIT 1 BY address"
        );

        let rows: Vec<EmbeddingRow> = self
            .client
            .query(&sql)
            .bind(chain.id())
            .bind(embedding_version)
            .fetch_all()
            .await?;

        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let stored = StoredEmbedding::try_from(row)?;
            out.insert(stored.address, stored);
        }
        Ok(out)
    }

    async fn nearest_candidates(
        &self,
        chain: Chain,
        embedding_version: &str,
        query: &[f32],
        exclude: &AccountAddress,
        limit: usize,
    ) -> Result<Vec<StoredEmbedding>, EmbeddingStoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let literal = vector_literal(query)?;

        // Three things about this query are load-bearing, and each was chosen
        // against an alternative that looks better and is not:
        //
        // 1. `cosineDistance` and nothing else. Migration 0007's index is
        //    declared with this distance function; any other one (L2Distance,
        //    say) silently falls back to a full scan.
        //
        // 2. The query vector is inlined, not bound. The `clickhouse` client
        //    renders a bound value through `Display`, so an f32 of `1.0`
        //    arrives as `1` and the whole literal parses as `Array(UInt8)` —
        //    which still *works*, returning correct rows, while quietly
        //    disabling the vector index. `vector_literal` renders through
        //    `Debug`, which always emits a float-typed literal. The values are
        //    our own computed floats, never caller text, so inlining is
        //    injection-safe (the `latest_many`/`neighbors_many` stance).
        //
        // 3. No `LIMIT 1 BY address`. The latest-per-address collapse the other
        //    reads do would make this an aggregate over the whole version
        //    partition, which the vector index cannot serve — the index only
        //    accelerates `ORDER BY <distance> LIMIT n` straight off the table.
        //    So the collapse moves into the caller, where it costs nothing.
        //
        // 4. Named columns, not `?fields`. The shortlist reads a narrower
        //    projection ([`CandidateRow`]) that omits the stored `top_factors`
        //    blob — see that type for why parsing it here would be ~1 MB of
        //    discarded JSON per request.
        let sql = format!(
            "SELECT {CANDIDATE_COLUMNS} FROM address_embeddings \
             WHERE chain = ? AND embedding_version = ? AND address != ? \
             ORDER BY cosineDistance(vector, {literal}) ASC \
             LIMIT ?"
        );

        let rows: Vec<CandidateRow> = self
            .client
            .query(&sql)
            .bind(chain.id())
            .bind(embedding_version)
            .bind(address_key(exclude))
            .bind(limit as u64)
            .fetch_all()
            .await?;

        rows.into_iter().map(StoredEmbedding::try_from).collect()
    }

    async fn cached_neighbors(
        &self,
        chain: Chain,
        address: &AccountAddress,
        embedding_version: &str,
    ) -> Result<Option<CachedNeighbors>, EmbeddingStoreError> {
        let row: Option<NeighborsRow> = self
            .client
            .query(
                "SELECT ?fields FROM address_neighbors \
                 WHERE chain = ? AND address = ? AND embedding_version = ? \
                 ORDER BY computed_at DESC LIMIT 1",
            )
            .bind(chain.id())
            .bind(address_key(address))
            .bind(embedding_version)
            .fetch_optional()
            .await?;
        row.map(CachedNeighbors::try_from).transpose()
    }

    async fn put_neighbors(
        &self,
        chain: Chain,
        entry: &CachedNeighbors,
    ) -> Result<(), EmbeddingStoreError> {
        let mut insert = self
            .client
            .insert::<NeighborsRow>("address_neighbors")
            .await?;
        insert
            .write(&NeighborsRow::from_entry(chain, entry))
            .await?;
        insert.end().await?;
        Ok(())
    }

    async fn sample_vectors(
        &self,
        chain: Chain,
        embedding_version: &str,
        limit: u32,
    ) -> Result<Vec<Vec<f32>>, EmbeddingStoreError> {
        // Latest-per-address first, then a bounded prefix in address order —
        // deterministic for a given (chain, version, limit), so a re-derived
        // baseline is reproducible rather than resampled.
        let rows: Vec<VectorOnlyRow> = self
            .client
            .query(
                "SELECT vector FROM ( \
                    SELECT address, vector FROM address_embeddings \
                      WHERE chain = ? AND embedding_version = ? \
                      ORDER BY address, computed_at DESC LIMIT 1 BY address \
                 ) LIMIT ?",
            )
            .bind(chain.id())
            .bind(embedding_version)
            .bind(u64::from(limit))
            .fetch_all()
            .await?;
        Ok(rows.into_iter().map(|row| row.vector).collect())
    }

    async fn put_baseline(
        &self,
        chain: Chain,
        baseline: &BehaviorBaseline,
    ) -> Result<(), EmbeddingStoreError> {
        let mut insert = self
            .client
            .insert::<BaselineRow>("behavior_baselines")
            .await?;
        insert
            .write(&BaselineRow::from_baseline(chain, baseline))
            .await?;
        insert.end().await?;
        Ok(())
    }

    async fn latest_baseline(
        &self,
        chain: Chain,
        embedding_version: &str,
    ) -> Result<Option<BehaviorBaseline>, EmbeddingStoreError> {
        let row: Option<BaselineRow> = self
            .client
            .query(
                "SELECT ?fields FROM behavior_baselines \
                 WHERE chain = ? AND embedding_version = ? \
                 ORDER BY computed_at DESC LIMIT 1",
            )
            .bind(chain.id())
            .bind(embedding_version)
            .fetch_optional()
            .await?;
        Ok(row.map(BehaviorBaseline::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedding::{default_embedder, BehaviorInputs};
    use alloy_primitives::Address;
    use event_bus::Transience;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn vector(entity_id: Option<EntityId>) -> BehaviorVector {
        default_embedder().embed(
            Address::repeat_byte(0x11),
            entity_id,
            &BehaviorInputs::default(),
            at(1_700_000_000),
        )
    }

    /// ClickHouse returns `RowBinary` columns **positionally**, so a field
    /// added to [`CandidateRow`] without a matching entry in
    /// `CANDIDATE_COLUMNS` — or in a different order — decodes the wrong
    /// column into the wrong field and produces plausible garbage rather than
    /// an error. The derive knows the field order; this pins the SQL to it.
    #[test]
    fn candidate_projection_matches_the_row_struct() {
        use clickhouse::Row;

        let declared: Vec<&str> = CANDIDATE_COLUMNS.split(',').map(str::trim).collect();
        assert_eq!(
            declared,
            CandidateRow::COLUMN_NAMES,
            "CANDIDATE_COLUMNS must list CandidateRow's fields in declaration order"
        );
    }

    /// The projection is narrower than the full row *on purpose*: it drops the
    /// stored `top_factors` blob the shortlist never reads. If this ever
    /// equals `EmbeddingRow`'s column set, the saving is gone.
    #[test]
    fn the_candidate_projection_is_strictly_narrower_than_the_full_row() {
        use clickhouse::Row;

        let full: std::collections::BTreeSet<_> = EmbeddingRow::COLUMN_NAMES.iter().collect();
        let projected: std::collections::BTreeSet<_> = CandidateRow::COLUMN_NAMES.iter().collect();

        assert!(projected.is_subset(&full), "projection must be a subset");
        assert!(
            !projected.contains(&"top_factors"),
            "the shortlist must not pay to parse the stored explanation"
        );
        assert!(
            projected.len() < full.len(),
            "a projection that selects everything is not a projection"
        );
    }

    /// A candidate decodes to the same comparable facts the full row does —
    /// everything the re-rank reads — and differs only in the factors blob it
    /// deliberately skips.
    #[test]
    fn a_candidate_row_agrees_with_the_full_row_on_everything_the_rerank_uses() {
        let entity_id = EntityId(uuid::Uuid::from_u128(0xE1));
        let vector = vector(Some(entity_id));
        let mut full = EmbeddingRow::from_vector(Chain::ETHEREUM, &vector);
        // A default-input vector is all zeros, which correctly has *no*
        // factors — so stamp a real explanation on, since the point here is
        // that the projection drops one that exists.
        full.top_factors = serde_json::to_string(&vec![BehaviorFactor {
            feature: "observation_count_log".into(),
            value: 1.5,
            share: 0.9,
        }])
        .expect("serialization is total");

        let candidate = CandidateRow {
            address: full.address.clone(),
            embedding_version: full.embedding_version.clone(),
            schema_hash: full.schema_hash.clone(),
            entity_id: full.entity_id.clone(),
            vector: full.vector.clone(),
            observations_truncated: full.observations_truncated,
            computed_at: full.computed_at,
        };

        let from_full = StoredEmbedding::try_from(full).expect("full row decodes");
        let from_candidate = StoredEmbedding::try_from(candidate).expect("candidate decodes");

        assert_eq!(from_candidate.address, from_full.address);
        assert_eq!(from_candidate.entity_id, from_full.entity_id);
        assert_eq!(from_candidate.values, from_full.values);
        assert_eq!(from_candidate.schema_hash, from_full.schema_hash);
        assert_eq!(from_candidate.computed_at, from_full.computed_at);
        assert_eq!(
            from_candidate.observations_truncated,
            from_full.observations_truncated
        );
        assert!(
            from_candidate.top_factors.is_empty() && !from_full.top_factors.is_empty(),
            "the projection skips the stored explanation the full row carries"
        );
    }

    #[test]
    fn row_maps_every_field_and_flattens_the_absent_entity() {
        let row = EmbeddingRow::from_vector(Chain::ETHEREUM, &vector(None));
        assert_eq!(row.chain, 1);
        assert_eq!(row.address, "0x1111111111111111111111111111111111111111");
        assert_eq!(row.embedding_version, crate::embedding::v1::VERSION);
        assert_eq!(row.schema_hash, crate::embedding::v1::SCHEMA.content_hash());
        assert_eq!(row.entity_id, "", "an unclustered address stores as ''");
        assert_eq!(row.vector.len(), crate::embedding::v1::SCHEMA.dimension());
        assert_eq!(row.observations_truncated, 0);
        assert_eq!(row.computed_at, at(1_700_000_000));
    }

    #[test]
    fn row_round_trips_back_to_the_stored_form() {
        let entity_id = EntityId(uuid::Uuid::from_u128(0xE1));
        let vector = vector(Some(entity_id));
        let back = StoredEmbedding::try_from(EmbeddingRow::from_vector(Chain::ETHEREUM, &vector))
            .expect("a freshly written row decodes");

        assert_eq!(back.address, vector.address);
        assert_eq!(back.entity_id, Some(entity_id));
        assert_eq!(back.values, vector.values);
        assert_eq!(back.top_factors, vector.to_event().top_factors);
        assert_eq!(back.computed_at, vector.computed_at);
    }

    /// Version *and* hash: a matching version with a different hash is exactly
    /// the accident (an edit to a frozen schema) a version string alone can't
    /// catch, and comparing across it would silently compute distances between
    /// two different feature spaces.
    #[test]
    fn matches_requires_both_the_version_and_the_schema_hash() {
        let stored =
            StoredEmbedding::try_from(EmbeddingRow::from_vector(Chain::ETHEREUM, &vector(None)))
                .expect("decodes");
        let version = crate::embedding::v1::VERSION;
        let hash = crate::embedding::v1::SCHEMA.content_hash().to_owned();

        assert!(stored.matches(version, &hash));
        assert!(!stored.matches(version, "a-different-schema"));
        assert!(!stored.matches("behavior-v2", &hash));
    }

    #[test]
    fn a_malformed_stored_row_is_permanent_not_transient() {
        let mut row = EmbeddingRow::from_vector(Chain::ETHEREUM, &vector(None));
        row.entity_id = "not-a-uuid".into();
        let err = StoredEmbedding::try_from(row).expect_err("a bad entity id is rejected");
        assert!(!err.is_transient());

        assert!(
            EmbeddingStoreError::Clickhouse(clickhouse::error::Error::Custom("io".into()))
                .is_transient()
        );
    }

    #[test]
    fn a_malformed_factors_blob_is_rejected_rather_than_silently_empty() {
        let mut row = EmbeddingRow::from_vector(Chain::ETHEREUM, &vector(None));
        row.top_factors = "{not json".into();
        assert!(StoredEmbedding::try_from(row).is_err());
    }
}
