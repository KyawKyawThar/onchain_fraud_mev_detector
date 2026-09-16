//! Row sizes measured from the event schema corpus.
//!
//! Every file under `crates/events/schema/corpus/<Event>/` is a real envelope,
//! replayed on every CI run (§17), so decoding it through
//! [`EventEnvelope::from_json_slice`] and re-encoding it the way the store does
//! gives the bytes a row actually costs — not a size someone estimated from a
//! struct definition and forgot to update when a field was added.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use events::{EventEnvelope, PartitionKey};
use serde::Serialize;

/// The `events` row's fixed-width columns (migrations 0001, 0002): `event_id`
/// 16, `schema_version` 2, `chain` 8, `occurred_at` 8, `appended_at` 8,
/// `Nullable(UUID)` `incident_id` 1 + 16, and the `addresses` array offset 8.
pub const FIXED_COLUMN_BYTES: u64 = 16 + 2 + 8 + 8 + 8 + 1 + 16 + 8;

/// One `addresses` element: `0x` + 40 hex digits and a length prefix.
const ADDRESS_BYTES: u64 = 42 + 1;

/// How a topic's records are keyed, which bounds its consumer parallelism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum KeyKind {
    /// Keyed by chain id: every record for a chain lands on one partition, so
    /// parallelism is at most the number of chains whatever the topic's size.
    Chain,
    /// Keyed by a high-cardinality business key (alert, incident, customer).
    Business,
}

/// The measured size of one event type — the largest of its corpus shapes.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Shape {
    /// The `payload` column: the `DomainEvent` as the store encodes it.
    pub payload_bytes: u64,
    /// Everything else in the row, uncompressed.
    pub column_bytes: u64,
    /// The whole envelope as a Kafka record value.
    pub envelope_bytes: u64,
    pub key: KeyKind,
    pub fixtures: usize,
}

pub type Shapes = BTreeMap<String, Shape>;

/// Measure every event type in the corpus at `dir`.
pub fn load(dir: &Path) -> Result<Shapes> {
    let mut shapes = Shapes::new();
    let mut types: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading the schema corpus at {}", dir.display()))?
        .collect::<Result<_, _>>()?;
    types.sort_by_key(std::fs::DirEntry::file_name);
    for entry in types {
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let event_type = entry.file_name().to_string_lossy().into_owned();
        let mut files: Vec<_> = std::fs::read_dir(entry.path())?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|f| f.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        for path in files {
            let bytes = std::fs::read(&path)?;
            let envelope = EventEnvelope::from_json_slice(&bytes)
                .with_context(|| format!("decoding corpus fixture {}", path.display()))?;
            ensure!(
                envelope.event_type() == event_type,
                "{} decodes as {}, not the {event_type} its directory names",
                path.display(),
                envelope.event_type()
            );
            let measured = measure(&envelope)?;
            shapes
                .entry(event_type.clone())
                .and_modify(|s| s.absorb(measured))
                .or_insert(measured);
        }
    }
    ensure!(
        !shapes.is_empty(),
        "no corpus shapes under {}",
        dir.display()
    );
    Ok(shapes)
}

/// The row and record size of one envelope.
pub fn measure(envelope: &EventEnvelope) -> Result<Shape> {
    let payload_bytes = serde_json::to_string(&envelope.payload)?.len() as u64;
    let envelope_bytes = envelope.to_json_vec()?.len() as u64;
    let strings = envelope.event_type().len() as u64
        + 1
        + envelope.payload.family().as_str().len() as u64
        + 1;
    let addresses = envelope.payload.addresses().len() as u64;
    let key = match envelope.partition_key() {
        PartitionKey::Chain(_) => KeyKind::Chain,
        _ => KeyKind::Business,
    };
    Ok(Shape {
        payload_bytes,
        column_bytes: FIXED_COLUMN_BYTES + strings + addresses * ADDRESS_BYTES,
        envelope_bytes,
        key,
        fixtures: 1,
    })
}

impl Shape {
    /// Fold another fixture of the same type in: sizes take the maximum (the
    /// corpus is small, so its largest shape is the conservative one), and a
    /// business key anywhere means the topic spreads.
    fn absorb(&mut self, other: Shape) {
        self.payload_bytes = self.payload_bytes.max(other.payload_bytes);
        self.column_bytes = self.column_bytes.max(other.column_bytes);
        self.envelope_bytes = self.envelope_bytes.max(other.envelope_bytes);
        if other.key == KeyKind::Business {
            self.key = KeyKind::Business;
        }
        self.fixtures += other.fixtures;
    }
}
