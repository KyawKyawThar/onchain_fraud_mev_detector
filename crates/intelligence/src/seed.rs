//! Label seeding from the §8.1 public sources (Sprint 7 t2): Etherscan tag
//! exports, the OFAC SDN digital-currency address list, community MEV-bot
//! lists and protocol address registries.
//!
//! Split pure-core / I/O-shell like everything else: each [`Feed`] variant has
//! a *pure* parser (`&str` → [`SeedBatch`], deterministic given the same file
//! and `now`), and the [`Seeder`] shell applies a batch through the t1 store
//! seams. Fetching the file is deliberately out of scope — feeds are
//! downloaded out-of-band (curl in the justfile) and handed to the CLI as a
//! path, so this crate needs no HTTP client and every parser test is hermetic.
//!
//! **Conflicting labels are stored, not overwritten** (§8.1) — and the
//! mechanism is the seeded label's *identity*: [`seeded_label_id`] derives the
//! `label_id` from the claim itself (`source_detail`, address, kind, value),
//! so re-importing the same feed is an idempotent no-op ([`LabelStore::add_label`]
//! keys on `label_id`), while a refreshed feed that *changed* a claim mints a
//! different id and lands as a **new row coexisting with the old one** — the
//! reader ranks by source/confidence, nothing is ever overwritten. Delistings
//! are likewise never deletions: a label that disappears from a feed simply
//! stops being re-asserted, and an authoritative withdrawal is a soft
//! [`LabelStore::revoke_label`] (operator curation, t4+).
//!
//! The OFAC feed is the §8.5 tie-in: it seeds `sanctions` rows (the exact-match
//! table behind the immediate `SanctionHit` hard alert) *and* the
//! `SanctionedEntity` labels. Event emission stays with the t4 consumer.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, LabelId};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::cache::{CacheError, HotCache};
use crate::model::{address_key, LabelKind, LabelRecord, LabelSource, SanctionEntry};
use crate::store::{LabelStore, SanctionsStore, StoreError};

/// The sanctions `list_name` OFAC rows are keyed under. Deliberately *not* the
/// operator-overridable `source_detail`: `(address, list_name)` is the upsert
/// key, so a per-import detail (e.g. a dated snapshot name) would fork the
/// list into duplicates instead of refreshing it (§8.5).
pub const OFAC_LIST_NAME: &str = "ofac_sdn";

/// The `entry` recorded for a bare-address OFAC import. The plain-text
/// digital-currency list carries no SDN entity names; a richer SDN parse can
/// upsert real names over these later (same `(address, list_name)` key).
const OFAC_ENTRY: &str = "OFAC SDN digital-currency address";

// ── Import metrics (§19) ─────────────────────────────────────────
// Recorded once per applied batch through the `metrics` facade — a no-op until
// a binary installs the exporter (`telemetry::metrics::init`), so the library
// and its tests stay exporter-agnostic. Monotonic counters: a scheduled
// re-import that inserts nothing shows up as a flat `inserted` series (drift
// detection), not a log line nobody reads.

/// Counter: labels newly inserted by seed imports.
pub const SEED_LABELS_INSERTED_TOTAL: &str = "intel_seed_labels_inserted_total";
/// Counter: labels whose exact claim was already stored (idempotent no-ops).
pub const SEED_LABELS_ALREADY_PRESENT_TOTAL: &str = "intel_seed_labels_already_present_total";
/// Counter: sanctions rows upserted by seed imports (§8.5).
pub const SEED_SANCTION_ROWS_TOTAL: &str = "intel_seed_sanction_rows_total";
/// Counter: distinct addresses evicted from the hot cache by seed imports.
pub const SEED_ADDRESSES_EVICTED_TOTAL: &str = "intel_seed_addresses_evicted_total";

/// A §8.1 public label feed and its parser. A closed enum — the CLI accepts
/// exactly these (kebab-case), and adding a source is a compile-checked new
/// variant, not a stringly-typed plugin.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
    strum::EnumIter,
)]
#[strum(serialize_all = "kebab-case")]
pub enum Feed {
    /// Etherscan-style tag export: CSV `address,kind,value` (quoted RFC-4180 —
    /// name tags contain commas), `kind` a [`LabelKind`] wire string.
    EtherscanTags,
    /// The OFAC SDN digital-currency address list: plain text, one address per
    /// line, `#` comments — the community-standard extraction of the SDN XML
    /// (e.g. 0xB10C/ofac-sanctioned-digital-currency-addresses). Seeds both
    /// sanctions rows (§8.5) and `SanctionedEntity` labels (§8.1).
    OfacSdn,
    /// Community MEV-bot list: JSON array of `{"address": …, "name": …}` →
    /// [`LabelKind::MevBot`] labels.
    MevList,
    /// Protocol address registry: JSON array of `{"address": …, "name": …}`
    /// with an optional `"kind"` (defaults to [`LabelKind::Protocol`]; a
    /// bridge registry says `"kind": "bridge"`).
    ProtocolRegistry,
}

impl Feed {
    /// The default `source_detail` provenance string for labels seeded from
    /// this feed — the audit trail of *which* feed made the claim (§8.1). The
    /// CLI lets an operator override it to name a specific list (there are
    /// many MEV lists and registries).
    pub fn canonical_detail(self) -> &'static str {
        match self {
            Feed::EtherscanTags => "etherscan_tags",
            Feed::OfacSdn => OFAC_LIST_NAME,
            Feed::MevList => "community_mev_list",
            Feed::ProtocolRegistry => "protocol_registry",
        }
    }

    /// Parse one downloaded feed file into the batch to seed. Pure: the same
    /// `raw`/`source_detail`/`now` always yield the same batch (including the
    /// same `label_id`s — see [`seeded_label_id`]), so an import is
    /// reproducible after the fact (§18).
    ///
    /// A malformed row is a *hard error* naming its location, not a skip: a
    /// silently half-imported compliance feed (OFAC especially) is worse than
    /// a loud one, and feeds are files an operator can fix and re-run.
    pub fn parse(
        self,
        raw: &str,
        source_detail: &str,
        now: DateTime<Utc>,
    ) -> Result<SeedBatch, ParseError> {
        let mut batch = match self {
            Feed::EtherscanTags => parse_etherscan_tags(raw, source_detail, now),
            Feed::OfacSdn => parse_ofac_sdn(raw, source_detail, now),
            Feed::MevList => parse_mev_list(raw, source_detail, now),
            Feed::ProtocolRegistry => parse_protocol_registry(raw, source_detail, now),
        }?;

        // In-batch dedup by identity, first occurrence wins — feeds do repeat
        // claims. Keeps the report honest ("already present" means *in the
        // store*, not "earlier in this file") and mirrors `seed_sanctions`'
        // in-batch dedup by its upsert key. Sanctions need no pass here: the
        // OFAC parser emits one row per input line and the store upserts.
        let mut seen = HashSet::with_capacity(batch.labels.len());
        batch.labels.retain(|label| seen.insert(label.label_id));
        Ok(batch)
    }
}

/// Where in a feed file a parse fault sits. Typed (not a prose string) so a
/// future operator API can return "fix line 12" structurally; `Display` is the
/// human rendering the CLI prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// A line of a CSV/plain-text feed (1-based, as editors count).
    Line(u64),
    /// An element of a JSON-array feed (0-based, as `jq` counts).
    Entry(usize),
    /// A JSON syntax fault, as reported by the decoder.
    LineColumn { line: usize, column: usize },
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Location::Line(line) => write!(f, "line {line}"),
            Location::Entry(index) => write!(f, "entry {index}"),
            Location::LineColumn { line, column } => write!(f, "line {line} column {column}"),
        }
    }
}

/// A feed file failed to parse. Always permanent — the file is bad; the fix is
/// a corrected file, never a retry — so unlike the store errors this carries a
/// *location*, not a retry decision.
#[derive(Debug, thiserror::Error)]
#[error("{feed} feed, {at}: {what}")]
pub struct ParseError {
    pub feed: Feed,
    pub at: Location,
    pub what: String,
}

impl ParseError {
    fn new(feed: Feed, at: Location, what: impl fmt::Display) -> Self {
        Self {
            feed,
            at,
            what: what.to_string(),
        }
    }
}

/// Everything one parsed feed wants stored: labels for every feed, plus
/// sanctions rows when the feed *is* a sanctions list (§8.5).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SeedBatch {
    pub labels: Vec<LabelRecord>,
    pub sanctions: Vec<SanctionEntry>,
}

/// Deterministic identity for a seeded label: SHA-256 over the claim
/// (`source_detail`, address, kind, value; length-prefixed so field boundaries
/// can't be forged), folded into a well-formed UUIDv8.
///
/// This is what makes seeding honour both halves of the §8.1 rule through the
/// existing `add_label` keying: the *same* claim re-imported maps to the same
/// `label_id` (idempotent no-op), a *different* claim — new value, new feed,
/// new kind — maps to a new id and coexists as its own row. `created_at` is
/// deliberately excluded: re-importing yesterday's feed today must still
/// no-op.
///
/// **The preimage recipe is a persistence contract.** Changing it (a new
/// field, a reordering, a different domain tag) silently re-mints every seeded
/// id, and the next import duplicates every seeded label in the store. Bump
/// the `.v1` domain tag *only* with a migration story; the golden test below
/// pins the exact bytes so a well-meaning refactor fails CI instead.
pub fn seeded_label_id(
    source_detail: &str,
    address: &AccountAddress,
    kind: LabelKind,
    value: &str,
) -> LabelId {
    let mut hasher = Sha256::new();
    hasher.update(b"mevwatch.seeded-label.v1");
    let addr = address_key(address);
    for field in [source_detail, addr.as_str(), <&str>::from(kind), value] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Stamp RFC 9562 version 8 ("custom") + variant bits so the id stays a
    // well-formed UUID next to the random v4s minted elsewhere.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    LabelId(Uuid::from_bytes(bytes))
}

/// Build one seeded label: external-feed provenance (§8.1's 0.4 confidence
/// band), deterministic id, no expiry (feeds don't carry one; withdrawal is
/// revocation, not `valid_until`).
fn seeded_label(
    address: AccountAddress,
    kind: LabelKind,
    value: String,
    source_detail: &str,
    now: DateTime<Utc>,
) -> LabelRecord {
    LabelRecord {
        label_id: seeded_label_id(source_detail, &address, kind, &value),
        address,
        kind,
        value,
        confidence: LabelSource::ExternalFeed.default_confidence(),
        source: LabelSource::ExternalFeed,
        source_detail: source_detail.to_owned(),
        created_at: now,
        valid_until: None,
    }
}

/// Parse a feed's address field (0x-hex, checksummed or not — feeds mix both;
/// storage normalizes to lowercase via [`address_key`]).
fn parse_feed_address(feed: Feed, at: Location, raw: &str) -> Result<AccountAddress, ParseError> {
    raw.parse()
        .map_err(|_| ParseError::new(feed, at, format!("address {raw:?} is not 0x-hex")))
}

// ── Per-feed parsers (pure) ──────────────────────────────────────

fn parse_etherscan_tags(
    raw: &str,
    source_detail: &str,
    now: DateTime<Utc>,
) -> Result<SeedBatch, ParseError> {
    const FEED: Feed = Feed::EtherscanTags;
    const EXPECTED_HEADER: [&str; 3] = ["address", "kind", "value"];

    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_reader(raw.as_bytes());

    let headers = reader
        .headers()
        .map_err(|err| ParseError::new(FEED, Location::Line(1), err))?;
    if headers.iter().ne(EXPECTED_HEADER) {
        return Err(ParseError::new(
            FEED,
            Location::Line(1),
            format!(
                "header must be exactly {:?}, got {:?}",
                EXPECTED_HEADER.join(","),
                headers.iter().collect::<Vec<_>>().join(",")
            ),
        ));
    }

    let mut labels = Vec::new();
    for record in reader.records() {
        // csv already rejects ragged rows (wrong field count) with a position.
        let record = record.map_err(|err| {
            let line = err.position().map_or(0, csv::Position::line);
            ParseError::new(FEED, Location::Line(line), err)
        })?;
        let at = Location::Line(record.position().map_or(0, csv::Position::line));

        let address = parse_feed_address(FEED, at, record.get(0).unwrap_or_default())?;
        let raw_kind = record.get(1).unwrap_or_default();
        let kind: LabelKind = raw_kind.parse().map_err(|_| {
            ParseError::new(
                FEED,
                at,
                format!("kind {raw_kind:?} is not a known label kind"),
            )
        })?;
        let value = record.get(2).unwrap_or_default();
        if value.is_empty() {
            return Err(ParseError::new(FEED, at, "value must not be empty"));
        }

        labels.push(seeded_label(
            address,
            kind,
            value.to_owned(),
            source_detail,
            now,
        ));
    }
    Ok(SeedBatch {
        labels,
        sanctions: Vec::new(),
    })
}

fn parse_ofac_sdn(
    raw: &str,
    source_detail: &str,
    now: DateTime<Utc>,
) -> Result<SeedBatch, ParseError> {
    const FEED: Feed = Feed::OfacSdn;

    let mut batch = SeedBatch::default();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = Location::Line(index as u64 + 1);
        let address = parse_feed_address(FEED, at, line)?;

        batch.sanctions.push(SanctionEntry {
            address,
            list_name: OFAC_LIST_NAME.to_owned(),
            entry: OFAC_ENTRY.to_owned(),
            listed_at: None,
        });
        batch.labels.push(seeded_label(
            address,
            LabelKind::SanctionedEntity,
            "OFAC SDN".to_owned(),
            source_detail,
            now,
        ));
    }
    Ok(batch)
}

/// One community MEV-list entry. Extra fields are tolerated — community JSON
/// carries all sorts of metadata; we take the claim we can store.
#[derive(serde::Deserialize)]
struct MevEntry {
    address: String,
    name: String,
}

fn parse_mev_list(
    raw: &str,
    source_detail: &str,
    now: DateTime<Utc>,
) -> Result<SeedBatch, ParseError> {
    const FEED: Feed = Feed::MevList;

    let entries: Vec<MevEntry> = parse_json_feed(FEED, raw)?;
    let mut labels = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let at = Location::Entry(index);
        let address = parse_feed_address(FEED, at, &entry.address)?;
        if entry.name.is_empty() {
            return Err(ParseError::new(FEED, at, "name must not be empty"));
        }
        labels.push(seeded_label(
            address,
            LabelKind::MevBot,
            entry.name.clone(),
            source_detail,
            now,
        ));
    }
    Ok(SeedBatch {
        labels,
        sanctions: Vec::new(),
    })
}

/// One protocol-registry entry: `kind` optional, defaulting to `Protocol`, so
/// a bridge registry can say `"kind": "bridge"` (§8.1's registry kinds).
#[derive(serde::Deserialize)]
struct RegistryEntry {
    address: String,
    name: String,
    kind: Option<LabelKind>,
}

fn parse_protocol_registry(
    raw: &str,
    source_detail: &str,
    now: DateTime<Utc>,
) -> Result<SeedBatch, ParseError> {
    const FEED: Feed = Feed::ProtocolRegistry;

    let entries: Vec<RegistryEntry> = parse_json_feed(FEED, raw)?;
    let mut labels = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let at = Location::Entry(index);
        let address = parse_feed_address(FEED, at, &entry.address)?;
        if entry.name.is_empty() {
            return Err(ParseError::new(FEED, at, "name must not be empty"));
        }
        labels.push(seeded_label(
            address,
            entry.kind.unwrap_or(LabelKind::Protocol),
            entry.name.clone(),
            source_detail,
            now,
        ));
    }
    Ok(SeedBatch {
        labels,
        sanctions: Vec::new(),
    })
}

/// Decode a JSON-array feed, mapping the syntax/shape error to its location.
fn parse_json_feed<T: serde::de::DeserializeOwned>(
    feed: Feed,
    raw: &str,
) -> Result<Vec<T>, ParseError> {
    serde_json::from_str(raw).map_err(|err| {
        ParseError::new(
            feed,
            Location::LineColumn {
                line: err.line(),
                column: err.column(),
            },
            err,
        )
    })
}

// ── Applying a batch (I/O shell) ─────────────────────────────────

/// A failure applying a parsed batch. Wraps the seam errors and forwards their
/// retry decision: an import that dies mid-batch is simply re-run — the
/// deterministic ids make the rerun converge instead of duplicating
/// (at-least-once + idempotent, the workspace contract).
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Cache(#[from] CacheError),
}

impl ApplyError {
    /// Whether re-running the import could plausibly succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            ApplyError::Store(err) => err.is_transient(),
            ApplyError::Cache(err) => err.is_transient(),
        }
    }
}

/// What one import did — the CLI's receipt, and the numbers a re-import is
/// judged by (a clean re-run inserts 0 and reports everything already
/// present).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeedReport {
    /// Labels newly stored.
    pub labels_inserted: u64,
    /// Labels whose exact claim was already stored (idempotent no-ops).
    pub labels_already_present: u64,
    /// Sanctions rows upserted (§8.5).
    pub sanction_rows: u64,
    /// Distinct addresses evicted from the hot cache (§8: evicted on update).
    pub addresses_evicted: u64,
}

impl fmt::Display for SeedReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "labels: {} inserted, {} already present; sanctions rows upserted: {}; \
             hot-cache addresses evicted: {}",
            self.labels_inserted,
            self.labels_already_present,
            self.sanction_rows,
            self.addresses_evicted
        )
    }
}

/// Applies a parsed [`SeedBatch`] through the t1 seams: sanctions first (the
/// §8.5 compliance rows land even if a later label write trips), then one
/// batched keyed label insert, then one pipelined hot-cache eviction for every
/// touched address (§8: eviction is correctness, the TTL only the backstop).
pub struct Seeder {
    labels: Arc<dyn LabelStore>,
    sanctions: Arc<dyn SanctionsStore>,
    cache: Arc<dyn HotCache>,
}

impl Seeder {
    pub fn new(
        labels: Arc<dyn LabelStore>,
        sanctions: Arc<dyn SanctionsStore>,
        cache: Arc<dyn HotCache>,
    ) -> Self {
        Self {
            labels,
            sanctions,
            cache,
        }
    }

    /// Apply one batch. Safe to re-run on any failure: every write is keyed
    /// (label ids are deterministic, sanctions upsert on `(address, list)`),
    /// so a retry converges on the same end state.
    #[tracing::instrument(
        skip_all,
        fields(labels = batch.labels.len(), sanctions = batch.sanctions.len())
    )]
    pub async fn apply(&self, batch: &SeedBatch) -> Result<SeedReport, ApplyError> {
        let sanction_rows = if batch.sanctions.is_empty() {
            0
        } else {
            self.sanctions.seed_sanctions(&batch.sanctions).await?
        };

        let labels_inserted = self.labels.add_labels(&batch.labels).await?;
        let labels_already_present = batch.labels.len() as u64 - labels_inserted;

        // Evict after the truth changed, deduped per address. An eviction
        // fault fails the import loudly (re-run; TTL backstops meanwhile)
        // rather than silently serving stale labels for the full TTL.
        let touched: BTreeSet<AccountAddress> = batch
            .labels
            .iter()
            .map(|label| label.address)
            .chain(batch.sanctions.iter().map(|entry| entry.address))
            .collect();
        let touched: Vec<AccountAddress> = touched.into_iter().collect();
        self.cache.evict_many(&touched).await?;

        let report = SeedReport {
            labels_inserted,
            labels_already_present,
            sanction_rows,
            addresses_evicted: touched.len() as u64,
        };
        record_import(&report);
        tracing::info!(
            inserted = report.labels_inserted,
            already_present = report.labels_already_present,
            sanction_rows = report.sanction_rows,
            evicted = report.addresses_evicted,
            "seed batch applied"
        );
        Ok(report)
    }
}

/// Bump the import counters from one applied batch (see the constants above).
fn record_import(report: &SeedReport) {
    metrics::counter!(SEED_LABELS_INSERTED_TOTAL).increment(report.labels_inserted);
    metrics::counter!(SEED_LABELS_ALREADY_PRESENT_TOTAL).increment(report.labels_already_present);
    metrics::counter!(SEED_SANCTION_ROWS_TOTAL).increment(report.sanction_rows);
    metrics::counter!(SEED_ADDRESSES_EVICTED_TOTAL).increment(report.addresses_evicted);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{InMemoryHotCache, InMemoryIntelligenceStore};
    use alloy_primitives::Address;
    use strum::IntoEnumIterator;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    // ── Feed CLI strings ────────────────────────────────────────

    /// The CLI names are kebab-case and round-trip — exhaustively, so a new
    /// feed variant is covered by construction.
    #[test]
    fn feed_names_round_trip() {
        for feed in Feed::iter() {
            let name = <&'static str>::from(feed);
            assert_eq!(name.parse::<Feed>().unwrap(), feed);
            assert!(!feed.canonical_detail().is_empty());
        }
        assert_eq!("ofac-sdn".parse::<Feed>().unwrap(), Feed::OfacSdn);
        assert_eq!(
            "etherscan-tags".parse::<Feed>().unwrap(),
            Feed::EtherscanTags
        );
    }

    // ── Deterministic identity ──────────────────────────────────

    #[test]
    fn seeded_label_id_is_deterministic_per_claim() {
        let address = addr(0x11);
        let id = seeded_label_id(
            "etherscan_tags",
            &address,
            LabelKind::CexWallet,
            "Binance 14",
        );
        // Same claim → same id (re-import no-ops)…
        assert_eq!(
            id,
            seeded_label_id(
                "etherscan_tags",
                &address,
                LabelKind::CexWallet,
                "Binance 14"
            )
        );
        // …any changed field → a different id (a new coexisting row).
        assert_ne!(
            id,
            seeded_label_id(
                "etherscan_tags",
                &address,
                LabelKind::CexWallet,
                "Binance 15"
            )
        );
        assert_ne!(
            id,
            seeded_label_id("etherscan_tags", &address, LabelKind::Bridge, "Binance 14")
        );
        assert_ne!(
            id,
            seeded_label_id("other_feed", &address, LabelKind::CexWallet, "Binance 14")
        );
        assert_ne!(
            id,
            seeded_label_id(
                "etherscan_tags",
                &addr(0x12),
                LabelKind::CexWallet,
                "Binance 14"
            )
        );
    }

    #[test]
    fn seeded_label_id_is_a_well_formed_uuid() {
        let id = seeded_label_id("feed", &addr(0x01), LabelKind::MevBot, "bot");
        assert_eq!(id.0.get_version_num(), 8);
        assert_eq!(id.0.get_variant(), uuid::Variant::RFC4122);
    }

    /// **Golden pin of the preimage recipe.** The id is a persistence
    /// contract: if this test fails, the change re-mints every seeded label id
    /// and the next feed import will duplicate every seeded row in `labels`.
    /// Do not update the expected value without a migration story.
    #[test]
    fn seeded_label_id_preimage_is_pinned() {
        let id = seeded_label_id(
            "etherscan_tags",
            &addr(0x11),
            LabelKind::CexWallet,
            "Binance 14",
        );
        assert_eq!(
            id.0.to_string(),
            "4722b3b2-80c4-866e-908d-d03cc39cc354",
            "seeded_label_id preimage changed — this re-mints every seeded id; \
             see the function docs before touching this"
        );
    }

    // ── Etherscan tags (CSV) ────────────────────────────────────

    #[test]
    fn etherscan_csv_parses_quoted_values_and_checksummed_addresses() {
        let raw = "address,kind,value\n\
                   0xABababABabABabABabABAbABabababABABABabAB,cex_wallet,\"Binance 14, hot\"\n\
                   0x1111111111111111111111111111111111111111,bridge,Wormhole\n";
        let batch = Feed::EtherscanTags
            .parse(raw, "etherscan_tags", at(1_000))
            .unwrap();

        assert!(batch.sanctions.is_empty());
        assert_eq!(batch.labels.len(), 2);
        let first = &batch.labels[0];
        assert_eq!(first.address, addr(0xAB));
        assert_eq!(first.kind, LabelKind::CexWallet);
        assert_eq!(first.value, "Binance 14, hot");
        assert_eq!(first.source, LabelSource::ExternalFeed);
        assert_eq!(first.confidence.get(), 0.4);
        assert_eq!(first.source_detail, "etherscan_tags");
        assert_eq!(first.created_at, at(1_000));
        assert_eq!(first.valid_until, None);
        assert_eq!(batch.labels[1].kind, LabelKind::Bridge);
    }

    #[test]
    fn etherscan_csv_rejects_bad_rows_with_their_line() {
        let header = "address,kind,value\n";
        let ok = "0x1111111111111111111111111111111111111111,mev_bot,bot\n";

        let bad_kind = format!("{header}{ok}0x2222222222222222222222222222222222222222,wat,x\n");
        let err = Feed::EtherscanTags
            .parse(&bad_kind, "d", at(0))
            .unwrap_err();
        assert_eq!(err.at, Location::Line(3), "got {err}");
        assert!(err.what.contains("wat"), "got {err}");

        let bad_address = format!("{header}nothex,mev_bot,x\n");
        let err = Feed::EtherscanTags
            .parse(&bad_address, "d", at(0))
            .unwrap_err();
        assert_eq!(err.at, Location::Line(2), "got {err}");

        let empty_value = format!("{header}0x1111111111111111111111111111111111111111,mev_bot,\n");
        let err = Feed::EtherscanTags
            .parse(&empty_value, "d", at(0))
            .unwrap_err();
        assert!(err.what.contains("empty"), "got {err}");

        let wrong_header = "addr,type,tag\n";
        let err = Feed::EtherscanTags
            .parse(wrong_header, "d", at(0))
            .unwrap_err();
        assert_eq!(err.at, Location::Line(1), "got {err}");
    }

    /// A feed that repeats the exact same claim yields it once — "already
    /// present" in the report must mean "in the store", not "earlier in this
    /// file".
    #[test]
    fn duplicate_claims_within_one_feed_are_deduped() {
        let raw = "address,kind,value\n\
                   0x1111111111111111111111111111111111111111,mev_bot,bot\n\
                   0x1111111111111111111111111111111111111111,mev_bot,bot\n\
                   0x1111111111111111111111111111111111111111,mev_bot,other-bot\n";
        let batch = Feed::EtherscanTags.parse(raw, "d", at(0)).unwrap();
        assert_eq!(batch.labels.len(), 2, "exact duplicate collapsed");
        assert_eq!(batch.labels[0].value, "bot");
        assert_eq!(batch.labels[1].value, "other-bot");
    }

    // ── OFAC SDN (plain text) ───────────────────────────────────

    #[test]
    fn ofac_list_seeds_sanctions_and_sanctioned_entity_labels() {
        let raw = "# Tornado Cash designations\n\
                   \n\
                   0x1111111111111111111111111111111111111111\n\
                   0x2222222222222222222222222222222222222222\n";
        let batch = Feed::OfacSdn.parse(raw, OFAC_LIST_NAME, at(5)).unwrap();

        assert_eq!(batch.sanctions.len(), 2);
        assert_eq!(batch.labels.len(), 2);
        assert_eq!(batch.sanctions[0].address, addr(0x11));
        assert_eq!(batch.sanctions[0].list_name, OFAC_LIST_NAME);
        assert_eq!(batch.labels[0].kind, LabelKind::SanctionedEntity);
        assert_eq!(batch.labels[0].source, LabelSource::ExternalFeed);
    }

    /// The sanctions upsert key must not follow an operator's `source_detail`
    /// override — a dated snapshot name would fork the list instead of
    /// refreshing it.
    #[test]
    fn ofac_list_name_ignores_detail_override() {
        let raw = "0x1111111111111111111111111111111111111111\n";
        let batch = Feed::OfacSdn
            .parse(raw, "ofac_sdn_2026-07-03", at(5))
            .unwrap();
        assert_eq!(batch.sanctions[0].list_name, OFAC_LIST_NAME);
        // …while the label provenance does record the specific import.
        assert_eq!(batch.labels[0].source_detail, "ofac_sdn_2026-07-03");
    }

    #[test]
    fn ofac_list_rejects_garbage_with_its_line() {
        let raw = "# comment\n0x1111111111111111111111111111111111111111\nnot-an-address\n";
        let err = Feed::OfacSdn.parse(raw, "d", at(0)).unwrap_err();
        assert_eq!(err.at, Location::Line(3), "got {err}");
    }

    // ── JSON feeds ──────────────────────────────────────────────

    #[test]
    fn mev_list_parses_and_tolerates_extra_fields() {
        let raw = r#"[
            {"address": "0x1111111111111111111111111111111111111111",
             "name": "jaredfromsubway", "note": "sandwich bot"},
            {"address": "0x2222222222222222222222222222222222222222", "name": "rsync"}
        ]"#;
        let batch = Feed::MevList
            .parse(raw, "community_mev_list", at(9))
            .unwrap();
        assert_eq!(batch.labels.len(), 2);
        assert!(batch
            .labels
            .iter()
            .all(|label| label.kind == LabelKind::MevBot));
        assert_eq!(batch.labels[0].value, "jaredfromsubway");
    }

    #[test]
    fn mev_list_rejects_bad_entries_with_their_index() {
        let raw = r#"[{"address": "nope", "name": "x"}]"#;
        let err = Feed::MevList.parse(raw, "d", at(0)).unwrap_err();
        assert_eq!(err.at, Location::Entry(0), "got {err}");

        let syntax = "[{";
        let err = Feed::MevList.parse(syntax, "d", at(0)).unwrap_err();
        assert!(
            matches!(err.at, Location::LineColumn { line: 1, .. }),
            "got {err}"
        );
    }

    #[test]
    fn protocol_registry_defaults_kind_and_accepts_overrides() {
        let raw = r#"[
            {"address": "0x1111111111111111111111111111111111111111", "name": "Uniswap V3: Router"},
            {"address": "0x2222222222222222222222222222222222222222", "name": "Wormhole: Portal",
             "kind": "bridge"}
        ]"#;
        let batch = Feed::ProtocolRegistry
            .parse(raw, "protocol_registry", at(3))
            .unwrap();
        assert_eq!(batch.labels[0].kind, LabelKind::Protocol);
        assert_eq!(batch.labels[1].kind, LabelKind::Bridge);

        let bad_kind = r#"[{"address": "0x1111111111111111111111111111111111111111",
                            "name": "x", "kind": "wat"}]"#;
        assert!(Feed::ProtocolRegistry.parse(bad_kind, "d", at(0)).is_err());
    }

    // ── Seeder over the in-memory seams ─────────────────────────

    fn seeder_over(
        store: &Arc<InMemoryIntelligenceStore>,
        cache: &Arc<InMemoryHotCache>,
    ) -> Seeder {
        Seeder::new(store.clone(), store.clone(), cache.clone())
    }

    /// Re-importing the same feed is a no-op; a refreshed feed with a changed
    /// claim *adds* a row — the old label is still there. This is the t2
    /// deliverable sentence: conflicting labels stored, not overwritten.
    #[tokio::test]
    async fn reimport_noops_and_changed_claims_coexist() {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let seeder = seeder_over(&store, &cache);

        let v1 = "address,kind,value\n\
                  0x1111111111111111111111111111111111111111,cex_wallet,Binance 14\n";
        let batch = Feed::EtherscanTags
            .parse(v1, "etherscan_tags", at(100))
            .unwrap();

        let first = seeder.apply(&batch).await.unwrap();
        assert_eq!(first.labels_inserted, 1);
        assert_eq!(first.labels_already_present, 0);

        // Same file, later import time: everything already present.
        let again = Feed::EtherscanTags
            .parse(v1, "etherscan_tags", at(200))
            .unwrap();
        let second = seeder.apply(&again).await.unwrap();
        assert_eq!(second.labels_inserted, 0);
        assert_eq!(second.labels_already_present, 1);

        // The feed re-tagged the address: both claims now coexist as rows.
        let v2 = "address,kind,value\n\
                  0x1111111111111111111111111111111111111111,cex_wallet,Binance 14 (retired)\n";
        let refreshed = Feed::EtherscanTags
            .parse(v2, "etherscan_tags", at(300))
            .unwrap();
        seeder.apply(&refreshed).await.unwrap();

        let labels = store.labels_for(&addr(0x11), at(1_000)).await.unwrap();
        let values: Vec<&str> = labels.iter().map(|label| label.value.as_str()).collect();
        assert_eq!(values, ["Binance 14", "Binance 14 (retired)"]);
    }

    /// A manual label and a feed label for the same address coexist too — the
    /// reader ranks by source/confidence, seeding never touches other rows.
    #[tokio::test]
    async fn seeded_labels_never_displace_manual_ones() {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let seeder = seeder_over(&store, &cache);

        let manual = LabelRecord::new(
            addr(0x11),
            LabelKind::CexWallet,
            "Binance cold storage (curated)",
            LabelSource::Manual,
            "operator:kkt",
            at(50),
        );
        store.add_label(&manual).await.unwrap();

        let raw = "address,kind,value\n\
                   0x1111111111111111111111111111111111111111,cex_wallet,Binance 14\n";
        let batch = Feed::EtherscanTags
            .parse(raw, "etherscan_tags", at(100))
            .unwrap();
        seeder.apply(&batch).await.unwrap();

        let labels = store.labels_for(&addr(0x11), at(1_000)).await.unwrap();
        assert_eq!(labels.len(), 2);
        assert!(labels
            .iter()
            .any(|label| label.source == LabelSource::Manual));
        assert!(labels
            .iter()
            .any(|label| label.source == LabelSource::ExternalFeed));
    }

    /// OFAC seeding lands both stores: the §8.5 exact-match sanctions rows and
    /// the §8.1 labels — and a re-import upserts instead of duplicating.
    #[tokio::test]
    async fn ofac_seed_populates_sanctions_and_labels_idempotently() {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let seeder = seeder_over(&store, &cache);

        let raw = "0x1111111111111111111111111111111111111111\n";
        let batch = Feed::OfacSdn.parse(raw, OFAC_LIST_NAME, at(10)).unwrap();
        let report = seeder.apply(&batch).await.unwrap();
        assert_eq!(report.sanction_rows, 1);
        assert_eq!(report.labels_inserted, 1);

        seeder
            .apply(&Feed::OfacSdn.parse(raw, OFAC_LIST_NAME, at(20)).unwrap())
            .await
            .unwrap();

        let matches = store.sanction_matches(&addr(0x11)).await.unwrap();
        assert_eq!(matches.len(), 1, "re-import must upsert, not duplicate");
        let labels = store.labels_for(&addr(0x11), at(1_000)).await.unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].kind, LabelKind::SanctionedEntity);
    }

    /// Seeding evicts touched addresses from the hot cache (§8: evicted on
    /// update) and leaves untouched ones alone.
    #[tokio::test]
    async fn seeding_evicts_touched_addresses_from_the_hot_cache() {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let seeder = seeder_over(&store, &cache);

        let stale = LabelRecord::new(
            addr(0x11),
            LabelKind::MevBot,
            "stale",
            LabelSource::Heuristic,
            "h",
            at(1),
        );
        cache
            .put_labels(&addr(0x11), std::slice::from_ref(&stale))
            .await
            .unwrap();
        cache.put_labels(&addr(0x22), &[stale]).await.unwrap();

        let raw = r#"[{"address": "0x1111111111111111111111111111111111111111", "name": "bot"}]"#;
        let report = seeder
            .apply(
                &Feed::MevList
                    .parse(raw, "community_mev_list", at(10))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(report.addresses_evicted, 1);
        assert_eq!(cache.labels(&addr(0x11)).await.unwrap(), None);
        assert!(cache.labels(&addr(0x22)).await.unwrap().is_some());
    }

    /// One applied batch bumps all four import counters (§19). Scoped local
    /// recorder + a current-thread runtime *inside* the closure: the recorder
    /// is thread-local, so the async work must stay on this thread.
    #[test]
    fn apply_records_the_import_counters() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(async {
                    let store = Arc::new(InMemoryIntelligenceStore::new());
                    let cache = Arc::new(InMemoryHotCache::new());
                    let seeder = seeder_over(&store, &cache);

                    let raw = "0x1111111111111111111111111111111111111111\n";
                    let batch = Feed::OfacSdn.parse(raw, OFAC_LIST_NAME, at(10)).unwrap();
                    // Twice: 1 insert + 1 already-present, 2 sanctions upserts.
                    seeder.apply(&batch).await.unwrap();
                    seeder.apply(&batch).await.unwrap();
                });
        });

        // One snapshot only — it drains the recorder.
        let series = snapshotter.snapshot().into_vec();
        let counter = |name: &str| -> u64 {
            series
                .iter()
                .find(|(key, _, _, _)| key.key().name() == name)
                .map(|(_, _, _, value)| match value {
                    DebugValue::Counter(n) => *n,
                    other => panic!("expected a counter, got {other:?}"),
                })
                .unwrap_or_else(|| panic!("counter {name} not recorded"))
        };

        assert_eq!(counter(SEED_LABELS_INSERTED_TOTAL), 1);
        assert_eq!(counter(SEED_LABELS_ALREADY_PRESENT_TOTAL), 1);
        assert_eq!(counter(SEED_SANCTION_ROWS_TOTAL), 2);
        assert_eq!(counter(SEED_ADDRESSES_EVICTED_TOTAL), 2);
    }
}
