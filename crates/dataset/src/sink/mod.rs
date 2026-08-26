//! The [`DatasetSink`] seam — where a materialised dataset lands.
//!
//! §20.1 names two destinations, and they answer different questions:
//!
//! - **ClickHouse** ([`clickhouse::ClickHouseSink`]) — the queryable copy. Slice
//!   a dataset by detector, outcome or fidelity; compare two windows; join
//!   against the usage/incident tables already there.
//! - **Parquet** ([`parquet::ParquetSink`]) — the offline-training handoff.
//!   "Model training itself happens offline; the contract between training and
//!   serving is the ONNX artifact plus its `feature_version`" — so the export
//!   has to hand a file to a stack that is not Rust, and Parquet is what pandas,
//!   Polars, Spark and every GBDT library read natively.
//!
//! Both write the same rows in the same order, so the manifest's
//! `content_hash` is a property of the *dataset*, never of the destination.
//! [`FanOutSink`] runs several at once for exactly that reason.
//!
//! Every sink also receives the [`DatasetManifest`] at [`DatasetSink::finish`],
//! and is expected to persist it alongside the rows: a feature matrix without
//! its schema, window and label rule is an anonymous pile of floats.

pub mod clickhouse;
pub mod parquet;

use async_trait::async_trait;

use crate::manifest::DatasetManifest;
use crate::row::DatasetRow;

/// A failure writing a dataset out.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("clickhouse write failed")]
    Clickhouse(#[from] ::clickhouse::error::Error),

    #[error("parquet write failed")]
    Parquet(#[from] ::parquet::errors::ParquetError),

    #[error("writing {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// A row's feature count disagrees with the schema the sink was opened for
    /// — a wiring bug (two granularities into one file), caught at the write
    /// rather than producing a silently ragged column.
    #[error("row has {found} features but this sink was opened for {expected}")]
    SchemaMismatch { expected: usize, found: usize },
}

/// Writes dataset rows somewhere durable.
///
/// `&mut self` (rather than `&self`) because the real sinks own a writer with
/// position — a Parquet file handle, a batch buffer — and pretending otherwise
/// would push interior mutability into every implementation for no gain.
#[async_trait]
pub trait DatasetSink: Send {
    /// Write a batch of rows, in order. Called repeatedly; order across calls
    /// is preserved.
    async fn write(&mut self, rows: &[DatasetRow]) -> Result<(), SinkError>;

    /// Flush, record the manifest, and close. Must be called exactly once, and
    /// a sink that is dropped without it has written an *unlabelled* pile of
    /// rows — hence the `#[must_use]` on the export's return value rather than
    /// a silent Drop impl that could swallow an error.
    async fn finish(&mut self, manifest: &DatasetManifest) -> Result<(), SinkError>;
}

/// Writes to several sinks in order, stopping at the first failure.
///
/// A partial fan-out failure leaves earlier sinks written and later ones not.
/// That is deliberate and safe here, because the remedy is simply to re-run the
/// same spec: the export is deterministic, so the second run re-produces
/// identical rows — the ClickHouse table's `ReplacingMergeTree` key collapses
/// what it already has, and the Parquet file is rewritten from scratch. Partial
/// failure costs time, never correctness.
#[derive(Default)]
pub struct FanOutSink {
    sinks: Vec<Box<dyn DatasetSink>>,
}

impl FanOutSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, sink: Box<dyn DatasetSink>) -> &mut Self {
        self.sinks.push(sink);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sinks.len()
    }
}

#[async_trait]
impl DatasetSink for FanOutSink {
    async fn write(&mut self, rows: &[DatasetRow]) -> Result<(), SinkError> {
        for sink in &mut self.sinks {
            sink.write(rows).await?;
        }
        Ok(())
    }

    async fn finish(&mut self, manifest: &DatasetManifest) -> Result<(), SinkError> {
        for sink in &mut self.sinks {
            sink.finish(manifest).await?;
        }
        Ok(())
    }
}

/// In-memory sink: the test double for this seam, and what `--dry-run` uses so
/// a spec can be validated end to end (replay, join, extraction, manifest)
/// without writing anything anywhere.
#[derive(Debug, Default)]
pub struct CollectingSink {
    pub rows: Vec<DatasetRow>,
    pub manifest: Option<DatasetManifest>,
}

impl CollectingSink {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DatasetSink for CollectingSink {
    async fn write(&mut self, rows: &[DatasetRow]) -> Result<(), SinkError> {
        self.rows.extend_from_slice(rows);
        Ok(())
    }

    async fn finish(&mut self, manifest: &DatasetManifest) -> Result<(), SinkError> {
        self.manifest = Some(manifest.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ctx::Fidelity;
    use crate::join::{Binding, JoinStats};
    use crate::label::Label;
    use crate::manifest::RowCounts;
    use crate::spec::DatasetSpec;
    use chrono::DateTime;
    use ml_features::Granularity;

    fn spec() -> DatasetSpec {
        DatasetSpec {
            chain: events::primitives::Chain::ETHEREUM,
            from: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            to: DateTime::from_timestamp(1_700_003_600, 0).unwrap(),
            feature_version: ml_features::FEATURE_VERSION,
            granularity: Granularity::Tx,
            min_fidelity: Fidelity::HeaderOnly,
            include_ambiguous: false,
            lookahead_secs: crate::spec::DEFAULT_LOOKAHEAD_SECS,
        }
    }

    pub(crate) fn row(seed: u128) -> DatasetRow {
        DatasetRow {
            dataset_id: "abcd".into(),
            trigger_event_id: uuid::Uuid::from_u128(seed),
            chain: 1,
            block_number: seed as u64,
            block_hash: alloy_primitives::B256::repeat_byte(seed as u8),
            occurred_at: DateTime::from_timestamp(1_700_000_100, 0).unwrap(),
            detector_id: "sandwich".into(),
            detector_version: "1.2.0".into(),
            detector_config_hash: "deadbeef".into(),
            tx_hash: Some(alloy_primitives::B256::repeat_byte(seed as u8)),
            alert_id: Some(uuid::Uuid::from_u128(seed + 100)),
            binding: Binding::Exact,
            fidelity: Fidelity::Enriched,
            feature_version: 1,
            granularity: "tx".into(),
            schema_hash: "0123".into(),
            features: vec![0.5, 1.25],
            label: Label::Positive,
            outcome: "confirmed".into(),
            raw_confidence: 0.8,
            profit: 1.0,
            victim_loss: 0.0,
        }
    }

    pub(crate) fn manifest(rows: &[DatasetRow]) -> DatasetManifest {
        DatasetManifest::new(
            &spec(),
            "0123".to_owned(),
            vec!["a".to_owned(), "b".to_owned()],
            {
                let mut d = crate::row::RowDigest::new();
                d.update_all(rows);
                d
            },
            RowCounts {
                written: rows.len() as u64,
                ..Default::default()
            },
            JoinStats::default(),
        )
    }

    #[tokio::test]
    async fn the_collecting_sink_preserves_row_order_across_batches() {
        let mut sink = CollectingSink::new();
        sink.write(&[row(1), row(2)]).await.unwrap();
        sink.write(&[row(3)]).await.unwrap();
        let rows: Vec<u128> = sink
            .rows
            .iter()
            .map(|r| r.trigger_event_id.as_u128())
            .collect();
        assert_eq!(rows, vec![1, 2, 3]);
        assert!(sink.manifest.is_none(), "not finished yet");
    }

    #[tokio::test]
    async fn fan_out_writes_the_same_rows_to_every_sink() {
        // Two collecting sinks behind a fan-out, driven once.
        struct Shared(std::sync::Arc<std::sync::Mutex<Vec<DatasetRow>>>);
        #[async_trait]
        impl DatasetSink for Shared {
            async fn write(&mut self, rows: &[DatasetRow]) -> Result<(), SinkError> {
                self.0.lock().unwrap().extend_from_slice(rows);
                Ok(())
            }
            async fn finish(&mut self, _: &DatasetManifest) -> Result<(), SinkError> {
                Ok(())
            }
        }

        let a = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let b = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut fan = FanOutSink::new();
        fan.push(Box::new(Shared(a.clone())));
        fan.push(Box::new(Shared(b.clone())));
        assert_eq!(fan.len(), 2);

        let rows = vec![row(1), row(2)];
        fan.write(&rows).await.unwrap();
        fan.finish(&manifest(&rows)).await.unwrap();

        assert_eq!(a.lock().unwrap().len(), 2);
        assert_eq!(*a.lock().unwrap(), *b.lock().unwrap());
    }
}
