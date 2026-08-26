//! The ClickHouse sink — the queryable copy of a dataset (§14).
//!
//! Two tables, both owned outright by this binary (§14: no shared tables):
//!
//! - `ml_dataset_rows` — the examples. `ReplacingMergeTree` keyed on
//!   `(dataset_id, block_number, trigger_event_id, tx_hash)`, so re-exporting a
//!   spec converges onto the same rows instead of doubling them. That is not a
//!   correctness crutch: re-export idempotency is a *consequence* of the
//!   pipeline being deterministic, and the engine choice is what lets an
//!   operator act on it (re-run a window after a schema fix without dropping a
//!   partition first).
//! - `ml_dataset_manifests` — one row per export run, carrying the spec, the
//!   feature names, the content hash, and the counts. A feature matrix without
//!   its schema is an anonymous pile of floats; this is where the meaning
//!   lives, and where "has this window already been exported, and did it come
//!   out the same?" is answered with a `SELECT`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clickhouse::Client;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::ClickhouseConfig;
use crate::manifest::DatasetManifest;
use crate::row::DatasetRow;
use crate::sink::{DatasetSink, SinkError};

/// Build the ClickHouse client from config. Does no I/O — the first real
/// connection happens on the first query. Kept separate from the sink so the
/// migration runner can use the same client (the event-store/usage pattern).
pub fn build_client(cfg: &ClickhouseConfig) -> Client {
    Client::default()
        .with_url(&cfg.url)
        .with_user(&cfg.user)
        .with_password(cfg.password.expose_secret())
        .with_database(&cfg.database)
}

/// The stored stand-in for "this row is block-granularity, so it names no
/// transaction". An empty string rather than a `Nullable(String)`: the column
/// is in the table's `ORDER BY` key, and ClickHouse's own guidance is against
/// nullable key columns (worse compression, no min/max skip index). No real
/// hash is empty, so the sentinel cannot collide — the same reasoning as
/// `usage`'s `NIL_CUSTOMER`.
pub const NO_TX: &str = "";

/// The all-zero UUID standing in for "no alert was bound" (a `Shadow`
/// detector's trigger), for the same reason: `alert_id` is queried constantly
/// and a real v4 id never lands on all-zero bits.
pub const NO_ALERT: Uuid = Uuid::nil();

/// One row of `ml_dataset_rows`. Field names are the column names.
///
/// `hex` strings rather than `FixedString(32)` for the hashes: every other
/// table in this system stores block/tx hashes as `0x`-prefixed lowercase hex
/// (event-store's `addresses` index does the same), and matching that means an
/// operator's `WHERE block_hash = '0x…'` works across tables without a
/// per-table encoding rule.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct DatasetRowRecord {
    pub dataset_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    pub trigger_event_id: Uuid,
    pub chain: u64,
    pub block_number: u64,
    pub block_hash: String,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub occurred_at: DateTime<Utc>,
    pub detector_id: String,
    pub detector_version: String,
    pub detector_config_hash: String,
    /// [`NO_TX`] for a block-granularity row.
    pub tx_hash: String,
    /// [`NO_ALERT`] when no alert was bound.
    #[serde(with = "clickhouse::serde::uuid")]
    pub alert_id: Uuid,
    pub binding: String,
    pub fidelity: String,
    pub feature_version: u32,
    pub granularity: String,
    pub schema_hash: String,
    /// Values in schema order. Names live once, on the manifest row — storing
    /// them per example would multiply a 24-string array across every row of a
    /// million-row dataset for no query the manifest cannot answer.
    pub features: Vec<f64>,
    pub label: u8,
    pub outcome: String,
    pub raw_confidence: f64,
    pub profit: f64,
    pub victim_loss: f64,
}

impl From<&DatasetRow> for DatasetRowRecord {
    fn from(row: &DatasetRow) -> Self {
        Self {
            dataset_id: row.dataset_id.clone(),
            trigger_event_id: row.trigger_event_id,
            chain: row.chain,
            block_number: row.block_number,
            block_hash: format!("{:#x}", row.block_hash),
            occurred_at: row.occurred_at,
            detector_id: row.detector_id.clone(),
            detector_version: row.detector_version.clone(),
            detector_config_hash: row.detector_config_hash.clone(),
            tx_hash: row
                .tx_hash
                .map_or_else(|| NO_TX.to_owned(), |hash| format!("{hash:#x}")),
            alert_id: row.alert_id.unwrap_or(NO_ALERT),
            binding: row.binding.as_str().to_owned(),
            fidelity: row.fidelity.as_str().to_owned(),
            feature_version: row.feature_version,
            granularity: row.granularity.clone(),
            schema_hash: row.schema_hash.clone(),
            features: row.features.clone(),
            label: row.label.as_u8(),
            outcome: row.outcome.clone(),
            raw_confidence: row.raw_confidence,
            profit: row.profit,
            victim_loss: row.victim_loss,
        }
    }
}

/// One row of `ml_dataset_manifests` — an export run's own record.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct ManifestRecord {
    pub dataset_id: String,
    /// The digest over the rows. Two runs of one spec produce the same value —
    /// which is what makes `SELECT uniqExact(content_hash) GROUP BY dataset_id`
    /// a reproducibility check anyone can run.
    pub content_hash: String,
    pub chain: u64,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub window_from: DateTime<Utc>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub window_to: DateTime<Utc>,
    pub feature_version: u32,
    pub granularity: String,
    pub schema_hash: String,
    pub feature_names: Vec<String>,
    pub label_rule: String,
    pub min_fidelity: String,
    pub include_ambiguous: u8,
    pub rows_written: u64,
    /// The full manifest as JSON — every count and histogram, without a column
    /// per bucket. The typed columns above are the ones worth indexing; this is
    /// the rest, kept verbatim so a manifest read back is the manifest written
    /// (the event-store `payload` discipline).
    pub manifest_json: String,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub generated_at: DateTime<Utc>,
    pub tool_version: String,
}

impl TryFrom<&DatasetManifest> for ManifestRecord {
    type Error = serde_json::Error;

    fn try_from(manifest: &DatasetManifest) -> Result<Self, Self::Error> {
        Ok(Self {
            dataset_id: manifest.dataset_id.clone(),
            content_hash: manifest.content_hash.clone(),
            chain: manifest.spec.chain.id(),
            window_from: manifest.spec.from,
            window_to: manifest.spec.to,
            feature_version: manifest.spec.feature_version.0,
            granularity: crate::spec::granularity_str(manifest.spec.granularity).to_owned(),
            schema_hash: manifest.feature_schema_hash.clone(),
            feature_names: manifest.feature_names.clone(),
            label_rule: manifest.label_rule.clone(),
            min_fidelity: manifest.spec.min_fidelity.as_str().to_owned(),
            include_ambiguous: u8::from(manifest.spec.include_ambiguous),
            rows_written: manifest.rows.written,
            manifest_json: serde_json::to_string(manifest)?,
            generated_at: manifest.generated_at,
            tool_version: manifest.tool_version.clone(),
        })
    }
}

/// Writes dataset rows into ClickHouse.
pub struct ClickHouseSink {
    client: Client,
}

impl ClickHouseSink {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Liveness probe — proves the server is reachable before an export spends
    /// minutes replaying a window it then cannot write.
    pub async fn ping(&self) -> Result<(), SinkError> {
        let _: u8 = self.client.query("SELECT 1").fetch_one().await?;
        Ok(())
    }

    /// The underlying client, for the read side (the integration tests, and
    /// `dataset verify`). Writes go through [`DatasetSink::write`].
    pub fn client(&self) -> &Client {
        &self.client
    }
}

#[async_trait]
impl DatasetSink for ClickHouseSink {
    /// One RowBinary insert per batch — one ClickHouse *part* per batch, not
    /// per row (the parts economics every sink in this workspace is sized
    /// around). The export chunks its rows; an empty batch is a no-op.
    async fn write(&mut self, rows: &[DatasetRow]) -> Result<(), SinkError> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut insert = self
            .client
            .insert::<DatasetRowRecord>("ml_dataset_rows")
            .await?;
        for row in rows {
            insert.write(&DatasetRowRecord::from(row)).await?;
        }
        insert.end().await?;
        Ok(())
    }

    async fn finish(&mut self, manifest: &DatasetManifest) -> Result<(), SinkError> {
        let record = ManifestRecord::try_from(manifest).map_err(|err| SinkError::Io {
            path: "ml_dataset_manifests".to_owned(),
            source: std::io::Error::other(err),
        })?;
        let mut insert = self
            .client
            .insert::<ManifestRecord>("ml_dataset_manifests")
            .await?;
        insert.write(&record).await?;
        insert.end().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::tests::{manifest, row};

    #[test]
    fn a_tx_row_maps_its_hashes_to_the_shared_hex_form() {
        let record = DatasetRowRecord::from(&row(1));
        assert!(
            record.block_hash.starts_with("0x") && record.block_hash.len() == 66,
            "{}",
            record.block_hash
        );
        assert_ne!(record.tx_hash, NO_TX);
        assert_eq!(record.features, vec![0.5, 1.25]);
        assert_eq!(record.label, 1);
    }

    #[test]
    fn absent_tx_and_alert_become_sentinels_not_nulls() {
        let mut source = row(1);
        source.tx_hash = None;
        source.alert_id = None;
        let record = DatasetRowRecord::from(&source);
        assert_eq!(record.tx_hash, NO_TX);
        assert_eq!(record.alert_id, NO_ALERT);
    }

    #[test]
    fn the_manifest_record_carries_both_typed_columns_and_the_verbatim_json() {
        let rows = vec![row(1), row(2)];
        let m = manifest(&rows);
        let record = ManifestRecord::try_from(&m).expect("serializes");

        assert_eq!(record.dataset_id, m.dataset_id);
        assert_eq!(record.content_hash, m.content_hash);
        assert_eq!(record.rows_written, 2);
        assert_eq!(record.feature_names, vec!["a", "b"]);
        assert_eq!(record.include_ambiguous, 0);

        // The JSON column round-trips to the same manifest — a read is the
        // write, so nothing is lost by the typed projection above it.
        let back: DatasetManifest =
            serde_json::from_str(&record.manifest_json).expect("round trip");
        assert_eq!(back, m);
    }
}
