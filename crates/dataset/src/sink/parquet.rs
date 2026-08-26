//! The Parquet sink — the offline-training handoff (§20.1).
//!
//! > *"Model training itself happens offline; the contract between training and
//! > serving is the ONNX artifact plus its `feature_version` — train in
//! > whatever stack fits, serve in Rust."*
//!
//! Which means the export has to hand a file to a stack that is not Rust.
//! Parquet is what pandas, Polars, DuckDB, Spark and every GBDT library read
//! natively, and it is columnar — so a feature matrix costs one contiguous
//! `double` column per feature rather than a row of boxed values.
//!
//! # Layout
//!
//! One column per provenance field, then **one `double` column per feature,
//! named exactly as the schema names it** (`tx_count_log`, `flow_concentration`,
//! …). No prefix, no `features[i]` array: a training script selects its inputs
//! by the same names the manifest, the model card and the serving-side
//! explainability surface use. Collisions with the provenance column names are
//! impossible to introduce by accident and are refused at open time
//! ([`ParquetSink::create`]) rather than producing a file with two columns of
//! the same name.
//!
//! # Why the low-level writer
//!
//! `parquet`'s arrow integration would mean building `RecordBatch`es — and the
//! entire arrow dependency subtree — to describe data that is already columnar
//! by the time it gets here. The column API writes each `Vec<f64>` straight
//! through, so the crate is compiled with `default-features = false` and the
//! workspace's dependency surface stays small.
//!
//! # Blocking I/O
//!
//! The writes are synchronous inside an `async fn`. That is a deliberate
//! exception to the workspace's never-block-the-reactor rule (§15) and it is
//! safe *here specifically*: this is a one-shot batch CLI whose runtime has no
//! other task to starve. It would not be acceptable in a service.

use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use parquet::basic::Compression;
use parquet::data_type::{ByteArray, ByteArrayType, DoubleType, Int32Type, Int64Type};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use parquet::schema::types::Type;

use crate::manifest::DatasetManifest;
use crate::row::DatasetRow;
use crate::sink::{DatasetSink, SinkError};

/// Provenance columns, in file order, before the feature columns. Kept as a
/// constant so the schema text, the write order and the collision check all
/// read from one list.
const PROVENANCE_COLUMNS: &[&str] = &[
    "dataset_id",
    "trigger_event_id",
    "chain",
    "block_number",
    "block_hash",
    "occurred_at",
    "detector_id",
    "detector_version",
    "detector_config_hash",
    "tx_hash",
    "alert_id",
    "binding",
    "fidelity",
    "feature_version",
    "granularity",
    "schema_hash",
    "label",
    "outcome",
    "raw_confidence",
    "profit",
    "victim_loss",
];

/// Rows buffered before a row group is flushed. Parquet's compression and
/// column statistics work per row group, so very small groups waste both;
/// 100k rows of ~24 doubles is a few tens of MB in memory, well inside the
/// budget a batch export already spends on its replay window.
pub const DEFAULT_ROW_GROUP_ROWS: usize = 100_000;

/// Writes a dataset to a Parquet file, plus a `<file>.manifest.json` sidecar.
///
/// The manifest is *also* embedded in the file's key-value metadata, so a
/// file that gets copied somewhere still carries its schema, window and label
/// rule. The sidecar exists because reading key-value metadata needs a Parquet
/// reader, and `cat` is often what an operator has.
pub struct ParquetSink {
    writer: Option<SerializedFileWriter<File>>,
    path: PathBuf,
    /// Feature names in schema order — the file's feature columns.
    feature_names: Vec<String>,
    /// Rows accumulated toward the next row group.
    buffer: Vec<DatasetRow>,
    row_group_rows: usize,
}

impl ParquetSink {
    /// Create the file and pin its schema to `feature_names`.
    ///
    /// Fails if a feature name would collide with a provenance column or is not
    /// a plain `[A-Za-z_][A-Za-z0-9_]*` identifier — both would produce a
    /// malformed or ambiguous schema, and both are better caught before a
    /// minute of replay than after.
    pub fn create(path: impl Into<PathBuf>, feature_names: Vec<String>) -> Result<Self, SinkError> {
        Self::create_with_row_group_size(path, feature_names, DEFAULT_ROW_GROUP_ROWS)
    }

    pub fn create_with_row_group_size(
        path: impl Into<PathBuf>,
        feature_names: Vec<String>,
        row_group_rows: usize,
    ) -> Result<Self, SinkError> {
        let path = path.into();
        validate_feature_names(&feature_names, &path)?;

        let schema = build_schema(&feature_names)?;
        let props = WriterProperties::builder()
            // Snappy: the one codec this crate is compiled with (the workspace
            // manifest enables `snap` and nothing else, so the writer stays
            // pure Rust). Feature columns of `double` compress modestly under
            // any codec; the win here is decode speed on the training side.
            .set_compression(Compression::SNAPPY)
            .build();

        let file = File::create(&path).map_err(|source| SinkError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let writer = SerializedFileWriter::new(file, Arc::new(schema), Arc::new(props))?;

        Ok(Self {
            writer: Some(writer),
            path,
            feature_names,
            buffer: Vec::new(),
            row_group_rows: row_group_rows.max(1),
        })
    }

    /// The file being written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The sidecar manifest path for `path`: `<path>.manifest.json`.
    pub fn manifest_path(path: &Path) -> PathBuf {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(".manifest.json");
        PathBuf::from(sidecar)
    }

    /// Write everything buffered as one row group.
    fn flush_row_group(&mut self) -> Result<(), SinkError> {
        let rows = std::mem::take(&mut self.buffer);
        self.write_row_group(&rows)
    }

    /// Write `rows` as one row group, column by column in schema order.
    fn write_row_group(&mut self, rows: &[DatasetRow]) -> Result<(), SinkError> {
        if rows.is_empty() {
            return Ok(());
        }
        let Some(writer) = self.writer.as_mut() else {
            return Ok(());
        };

        let mut group = writer.next_row_group()?;
        let mut column = 0usize;
        // Columns are consumed in schema order; `next_column` handing back
        // `None` before we are done would mean the schema and this loop
        // disagree, which `SchemaMismatch` reports rather than silently
        // truncating.
        while let Some(mut writer) = group.next_column()? {
            write_column(&mut writer, column, rows, self.feature_names.len())?;
            writer.close()?;
            column += 1;
        }
        group.close()?;
        Ok(())
    }
}

/// Reject names that cannot be schema columns, before the file is created.
fn validate_feature_names(names: &[String], path: &Path) -> Result<(), SinkError> {
    let reserved: BTreeSet<&str> = PROVENANCE_COLUMNS.iter().copied().collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for name in names {
        let ok_ident = !name.is_empty()
            && name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !ok_ident || reserved.contains(name.as_str()) || !seen.insert(name.as_str()) {
            return Err(SinkError::Io {
                path: path.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "feature name {name:?} cannot be a Parquet column here — it must be a \
                         plain identifier, unique, and not one of the provenance columns"
                    ),
                ),
            });
        }
    }
    Ok(())
}

/// The message type: provenance columns then one `double` per feature.
fn build_schema(feature_names: &[String]) -> Result<Type, SinkError> {
    let mut text = String::from("message dataset_row {\n");
    text.push_str(
        "  REQUIRED BYTE_ARRAY dataset_id (UTF8);\n\
         \x20 REQUIRED BYTE_ARRAY trigger_event_id (UTF8);\n\
         \x20 REQUIRED INT64 chain;\n\
         \x20 REQUIRED INT64 block_number;\n\
         \x20 REQUIRED BYTE_ARRAY block_hash (UTF8);\n\
         \x20 REQUIRED INT64 occurred_at (TIMESTAMP_MILLIS);\n\
         \x20 REQUIRED BYTE_ARRAY detector_id (UTF8);\n\
         \x20 REQUIRED BYTE_ARRAY detector_version (UTF8);\n\
         \x20 REQUIRED BYTE_ARRAY detector_config_hash (UTF8);\n\
         \x20 REQUIRED BYTE_ARRAY tx_hash (UTF8);\n\
         \x20 REQUIRED BYTE_ARRAY alert_id (UTF8);\n\
         \x20 REQUIRED BYTE_ARRAY binding (UTF8);\n\
         \x20 REQUIRED BYTE_ARRAY fidelity (UTF8);\n\
         \x20 REQUIRED INT32 feature_version;\n\
         \x20 REQUIRED BYTE_ARRAY granularity (UTF8);\n\
         \x20 REQUIRED BYTE_ARRAY schema_hash (UTF8);\n\
         \x20 REQUIRED INT32 label;\n\
         \x20 REQUIRED BYTE_ARRAY outcome (UTF8);\n\
         \x20 REQUIRED DOUBLE raw_confidence;\n\
         \x20 REQUIRED DOUBLE profit;\n\
         \x20 REQUIRED DOUBLE victim_loss;\n",
    );
    for name in feature_names {
        text.push_str(&format!("  REQUIRED DOUBLE {name};\n"));
    }
    text.push('}');
    Ok(parse_message_type(&text)?)
}

/// Write column `index` of `rows`. The `match` mirrors [`PROVENANCE_COLUMNS`]
/// by position; anything past it is feature column `index -
/// PROVENANCE_COLUMNS.len()`.
fn write_column(
    writer: &mut parquet::file::writer::SerializedColumnWriter<'_>,
    index: usize,
    rows: &[DatasetRow],
    feature_count: usize,
) -> Result<(), SinkError> {
    fn utf8(values: Vec<String>) -> Vec<ByteArray> {
        // `ByteArray` converts from `Vec<u8>`, not `String` — the UTF8 logical
        // type in the schema is what tells a reader to decode these as text.
        values
            .into_iter()
            .map(|s| ByteArray::from(s.into_bytes()))
            .collect()
    }

    match index {
        0 => strings(
            writer,
            utf8(rows.iter().map(|r| r.dataset_id.clone()).collect()),
        )?,
        1 => strings(
            writer,
            utf8(
                rows.iter()
                    .map(|r| r.trigger_event_id.to_string())
                    .collect(),
            ),
        )?,
        2 => ints64(writer, rows.iter().map(|r| r.chain as i64).collect())?,
        3 => ints64(writer, rows.iter().map(|r| r.block_number as i64).collect())?,
        4 => strings(
            writer,
            utf8(
                rows.iter()
                    .map(|r| format!("{:#x}", r.block_hash))
                    .collect(),
            ),
        )?,
        5 => ints64(
            writer,
            rows.iter()
                .map(|r| r.occurred_at.timestamp_millis())
                .collect(),
        )?,
        6 => strings(
            writer,
            utf8(rows.iter().map(|r| r.detector_id.clone()).collect()),
        )?,
        7 => strings(
            writer,
            utf8(rows.iter().map(|r| r.detector_version.clone()).collect()),
        )?,
        8 => strings(
            writer,
            utf8(
                rows.iter()
                    .map(|r| r.detector_config_hash.clone())
                    .collect(),
            ),
        )?,
        9 => strings(
            writer,
            utf8(
                rows.iter()
                    .map(|r| r.tx_hash.map(|h| format!("{h:#x}")).unwrap_or_default())
                    .collect(),
            ),
        )?,
        10 => strings(
            writer,
            utf8(
                rows.iter()
                    .map(|r| r.alert_id.map(|a| a.to_string()).unwrap_or_default())
                    .collect(),
            ),
        )?,
        11 => strings(
            writer,
            utf8(rows.iter().map(|r| r.binding.as_str().to_owned()).collect()),
        )?,
        12 => strings(
            writer,
            utf8(
                rows.iter()
                    .map(|r| r.fidelity.as_str().to_owned())
                    .collect(),
            ),
        )?,
        13 => ints32(
            writer,
            rows.iter().map(|r| r.feature_version as i32).collect(),
        )?,
        14 => strings(
            writer,
            utf8(rows.iter().map(|r| r.granularity.clone()).collect()),
        )?,
        15 => strings(
            writer,
            utf8(rows.iter().map(|r| r.schema_hash.clone()).collect()),
        )?,
        16 => ints32(
            writer,
            rows.iter().map(|r| i32::from(r.label.as_u8())).collect(),
        )?,
        17 => strings(
            writer,
            utf8(rows.iter().map(|r| r.outcome.clone()).collect()),
        )?,
        18 => doubles(writer, rows.iter().map(|r| r.raw_confidence).collect())?,
        19 => doubles(writer, rows.iter().map(|r| r.profit).collect())?,
        20 => doubles(writer, rows.iter().map(|r| r.victim_loss).collect())?,
        other => {
            let feature = other - PROVENANCE_COLUMNS.len();
            let mut values = Vec::with_capacity(rows.len());
            for row in rows {
                let value = row.features.get(feature).copied().ok_or({
                    SinkError::SchemaMismatch {
                        expected: feature_count,
                        found: row.features.len(),
                    }
                })?;
                values.push(value);
            }
            doubles(writer, values)?
        }
    }
    Ok(())
}

fn strings(
    writer: &mut parquet::file::writer::SerializedColumnWriter<'_>,
    values: Vec<ByteArray>,
) -> Result<(), SinkError> {
    writer
        .typed::<ByteArrayType>()
        .write_batch(&values, None, None)?;
    Ok(())
}

fn ints64(
    writer: &mut parquet::file::writer::SerializedColumnWriter<'_>,
    values: Vec<i64>,
) -> Result<(), SinkError> {
    writer
        .typed::<Int64Type>()
        .write_batch(&values, None, None)?;
    Ok(())
}

fn ints32(
    writer: &mut parquet::file::writer::SerializedColumnWriter<'_>,
    values: Vec<i32>,
) -> Result<(), SinkError> {
    writer
        .typed::<Int32Type>()
        .write_batch(&values, None, None)?;
    Ok(())
}

fn doubles(
    writer: &mut parquet::file::writer::SerializedColumnWriter<'_>,
    values: Vec<f64>,
) -> Result<(), SinkError> {
    writer
        .typed::<DoubleType>()
        .write_batch(&values, None, None)?;
    Ok(())
}

#[async_trait]
impl DatasetSink for ParquetSink {
    async fn write(&mut self, rows: &[DatasetRow]) -> Result<(), SinkError> {
        for row in rows {
            if row.features.len() != self.feature_names.len() {
                return Err(SinkError::SchemaMismatch {
                    expected: self.feature_names.len(),
                    found: row.features.len(),
                });
            }
        }
        self.buffer.extend_from_slice(rows);
        while self.buffer.len() >= self.row_group_rows {
            // `split_off` leaves the first `row_group_rows` in `buffer` and
            // hands back the remainder; swap so `group` holds the full batch
            // and `buffer` keeps what is left over for the next group.
            let remainder = self.buffer.split_off(self.row_group_rows);
            let group = std::mem::replace(&mut self.buffer, remainder);
            self.write_row_group(&group)?;
        }
        Ok(())
    }

    async fn finish(&mut self, manifest: &DatasetManifest) -> Result<(), SinkError> {
        self.flush_row_group()?;

        let manifest_json =
            serde_json::to_string_pretty(manifest).map_err(|err| SinkError::Io {
                path: self.path.display().to_string(),
                source: std::io::Error::other(err),
            })?;

        if let Some(mut writer) = self.writer.take() {
            // Embedded copy, so a file moved on its own still explains itself.
            writer.append_key_value_metadata(parquet::file::metadata::KeyValue::new(
                "dataset_manifest".to_owned(),
                manifest_json.clone(),
            ));
            writer.close()?;
        }

        // Sidecar copy, readable without a Parquet reader.
        let sidecar = Self::manifest_path(&self.path);
        std::fs::write(&sidecar, manifest_json).map_err(|source| SinkError::Io {
            path: sidecar.display().to_string(),
            source,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::tests::{manifest, row};

    use parquet::file::reader::{FileReader, SerializedFileReader};

    fn names() -> Vec<String> {
        vec!["a".to_owned(), "b".to_owned()]
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("dataset-{}-{}.parquet", name, uuid::Uuid::new_v4()));
        path
    }

    #[test]
    fn a_feature_name_colliding_with_a_provenance_column_is_refused_at_open() {
        let path = temp_path("collision");
        // `ParquetSink` owns a file writer and so isn't `Debug`; match rather
        // than `expect_err`.
        let Err(err) = ParquetSink::create(&path, vec!["label".to_owned()]) else {
            panic!("a feature named after a provenance column must be refused");
        };
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "{err}"
        );
        assert!(!path.exists(), "the file must not be created on refusal");
    }

    #[test]
    fn duplicate_and_malformed_feature_names_are_refused() {
        for bad in [
            vec!["a".to_owned(), "a".to_owned()],
            vec!["9lives".to_owned()],
            vec!["has space".to_owned()],
            vec![String::new()],
        ] {
            let path = temp_path("bad");
            assert!(
                ParquetSink::create(&path, bad.clone()).is_err(),
                "should refuse {bad:?}"
            );
            assert!(!path.exists(), "no file for {bad:?}");
        }
    }

    #[tokio::test]
    async fn a_row_whose_width_disagrees_with_the_schema_is_refused_not_padded() {
        let path = temp_path("width");
        let mut sink = ParquetSink::create(&path, names()).expect("creates");
        let mut wrong = row(1);
        wrong.features = vec![0.5];
        let err = sink.write(&[wrong]).await.expect_err("must refuse");
        assert!(
            matches!(
                err,
                SinkError::SchemaMismatch {
                    expected: 2,
                    found: 1
                }
            ),
            "{err}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn rows_land_in_the_file_with_the_manifest_beside_and_inside_it() {
        let path = temp_path("roundtrip");
        let rows = vec![row(1), row(2), row(3)];
        let m = manifest(&rows);

        let mut sink = ParquetSink::create_with_row_group_size(&path, names(), 2).expect("creates");
        sink.write(&rows[..2]).await.expect("first batch");
        sink.write(&rows[2..]).await.expect("second batch");
        sink.finish(&m).await.expect("finishes");

        let file = File::open(&path).expect("open");
        let reader = SerializedFileReader::new(file).expect("read");
        let metadata = reader.metadata();
        assert_eq!(
            metadata.file_metadata().num_rows(),
            3,
            "every row written, across two row groups"
        );
        assert!(
            metadata.num_row_groups() >= 2,
            "the row-group size was honoured: {}",
            metadata.num_row_groups()
        );

        // The schema is provenance columns then one column per feature name.
        let schema = metadata.file_metadata().schema_descr();
        let columns: Vec<String> = (0..schema.num_columns())
            .map(|i| schema.column(i).name().to_owned())
            .collect();
        assert_eq!(&columns[..PROVENANCE_COLUMNS.len()], PROVENANCE_COLUMNS);
        assert_eq!(&columns[PROVENANCE_COLUMNS.len()..], &["a", "b"]);

        // Embedded manifest.
        let embedded = metadata
            .file_metadata()
            .key_value_metadata()
            .expect("key-value metadata")
            .iter()
            .find(|kv| kv.key == "dataset_manifest")
            .and_then(|kv| kv.value.clone())
            .expect("dataset_manifest entry");
        let back: DatasetManifest = serde_json::from_str(&embedded).expect("parse");
        assert_eq!(back, m);

        // Sidecar manifest.
        let sidecar = ParquetSink::manifest_path(&path);
        let text = std::fs::read_to_string(&sidecar).expect("sidecar written");
        let side: DatasetManifest = serde_json::from_str(&text).expect("parse sidecar");
        assert_eq!(side, m);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&sidecar);
    }

    #[tokio::test]
    async fn an_empty_dataset_still_produces_a_readable_file_and_a_manifest() {
        let path = temp_path("empty");
        let m = manifest(&[]);
        let mut sink = ParquetSink::create(&path, names()).expect("creates");
        sink.finish(&m).await.expect("finishes");

        let reader = SerializedFileReader::new(File::open(&path).expect("open")).expect("read");
        assert_eq!(reader.metadata().file_metadata().num_rows(), 0);
        assert!(ParquetSink::manifest_path(&path).exists());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(ParquetSink::manifest_path(&path));
    }
}
