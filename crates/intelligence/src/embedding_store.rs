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

/// Just the `vector` column — the baseline sample read's row shape.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct VectorOnlyRow {
    vector: Vec<f32>,
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
