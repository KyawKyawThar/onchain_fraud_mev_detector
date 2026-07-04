//! The Postgres system of record (§8, §14, Sprint 7 t1): labels with
//! provenance, versioned entities + membership, attribution records and
//! sanctions lists — each behind an object-safe seam so the t2–t5 consumers
//! are tested against in-memory doubles with no database.
//!
//! Write discipline mirrors the simulation store: every write is keyed on a
//! stable id (`label_id`, `entity_id`, `(incident_id, entity_id)`,
//! `(address, list_name)`) so a redelivered event is an idempotent no-op — the
//! §7/§8 at-least-once contract. The one *transactional* primitive is
//! [`EntityStore::absorb`]: a merge moves membership, tombstones the absorbed
//! entity and bumps the survivor's `version` atomically, so the
//! "address belongs to at most one entity" invariant (the `entity_addresses`
//! primary key) holds at every instant. Serializing merges *per entity* is the
//! t5 actor's job — this store only guarantees each merge is atomic.

use std::str::FromStr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, Confidence, EntityId, IncidentId, LabelId};
use sqlx::PgPool;

use sqlx::types::Uuid;

use crate::model::{
    address_key, parse_address_key, AddressKeyError, AttributionRecord, EntityRecord, EntityStatus,
    LabelRecord, SanctionEntry,
};

/// A failure reading or writing the Postgres store. Carries the retry/skip
/// *decision* ([`is_transient`](Self::is_transient)) so every consumer handles
/// faults uniformly — the same contract as the simulation store and
/// event-store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A Postgres round-trip failed. Usually transient (connection/pool/
    /// server), but an encoding/schema fault is a bug that fails identically
    /// on every retry.
    #[error("postgres round-trip failed")]
    Postgres(#[from] sqlx::Error),

    /// A stored value no longer parses into its domain type (an enum string,
    /// address or confidence written by a newer/older build). Permanent: the
    /// row itself is bad, retrying re-reads the same bytes.
    #[error("stored value is malformed: {what}")]
    Malformed { what: String },
}

impl From<AddressKeyError> for StoreError {
    fn from(err: AddressKeyError) -> Self {
        StoreError::Malformed {
            what: err.to_string(),
        }
    }
}

impl StoreError {
    fn malformed(what: impl Into<String>) -> Self {
        StoreError::Malformed { what: what.into() }
    }

    /// Whether retrying the same operation could plausibly succeed later. A
    /// transient fault is retried/redelivered; a permanent one (an
    /// encoding/schema/parse bug that fails identically every time) is skipped
    /// so it can't wedge the stream (§4). Postgres faults classify through the
    /// shared [`db::is_permanent`] so the decision can't drift across services.
    pub fn is_transient(&self) -> bool {
        match self {
            StoreError::Malformed { .. } => false,
            StoreError::Postgres(err) => !db::is_permanent(err),
        }
    }
}

/// What creating an entity did (§8.2). Speaks the domain so the clustering
/// caller (t3) can branch without decoding SQL constraint violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateOutcome {
    /// Entity + seed membership written.
    Created,
    /// This `entity_id` already exists — an idempotent redelivery no-op.
    AlreadyExists,
    /// The seed address already belongs to that other entity; nothing written.
    /// The caller wanted a *merge*, not a create.
    SeedOwnedBy(EntityId),
}

/// What linking an address to an entity did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOutcome {
    Linked,
    /// Already a member of this same entity — idempotent no-op.
    AlreadyMember,
    /// Owned by another entity: the membership invariant blocked the link. The
    /// caller decides whether that means "merge these entities" (t3/t5).
    OwnedBy(EntityId),
}

/// What an [`EntityStore::absorb`] merge did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Membership moved, absorbed tombstoned, survivor's version bumped.
    Merged { survivor_version: u64 },
    /// The absorbed entity is missing or already absorbed — an idempotent
    /// no-op on a redelivered merge.
    AbsorbedInactive,
    /// The survivor is missing or itself absorbed; nothing written.
    SurvivorInactive,
    /// `surviving == absorbed` — a self-merge is meaningless and rejected.
    SelfMerge,
}

/// Wallet labels with provenance (§8.1). Conflicting labels coexist; the only
/// mutation ever applied to a label row is revocation (soft, audited).
#[async_trait]
pub trait LabelStore: Send + Sync {
    /// Insert a label, keyed by its `label_id`. Returns `false` when the id is
    /// already stored — a redelivered `LabelAdded` is a no-op.
    async fn add_label(&self, label: &LabelRecord) -> Result<bool, StoreError>;

    /// Insert many keyed labels; returns how many were *new* (the rest were
    /// already stored — `len - new` is the idempotent-no-op count). The
    /// default loops over [`add_label`](Self::add_label) so every double stays
    /// correct by construction; [`PgIntelligenceStore`] overrides it with one
    /// UNNEST statement — feed imports (§8.1) are OFAC/Etherscan-scale, and
    /// per-row round-trips are not a production path (same rule as
    /// [`SanctionsStore::seed_sanctions`]).
    ///
    /// Callers should deduplicate by `label_id` first (the seed parsers do):
    /// an in-slice duplicate is *counted* as already-present, muddying the
    /// report even though the write itself stays correct.
    async fn add_labels(&self, labels: &[LabelRecord]) -> Result<u64, StoreError> {
        let mut inserted = 0;
        for label in labels {
            if self.add_label(label).await? {
                inserted += 1;
            }
        }
        Ok(inserted)
    }

    /// All labels *active as of the given instant* for an address — created by
    /// then, not expired by then — every conflicting claim, newest last; the
    /// reader ranks by source/confidence. `as_of` is an explicit input (not an
    /// ambient clock) so the same call is deterministic in replay/backtests
    /// (§18): a live consumer passes `Utc::now()`, replay passes the event's
    /// `occurred_at`. Revoked labels are excluded regardless of `as_of` —
    /// revocation is an authoritative withdrawal (the label was *wrong*), and
    /// a wrong label must not resurface in replay.
    async fn labels_for(
        &self,
        address: &AccountAddress,
        as_of: DateTime<Utc>,
    ) -> Result<Vec<LabelRecord>, StoreError>;

    /// Revoke a label (soft: the row is kept for audit). Returns `false` when
    /// it was already revoked or never existed — idempotent.
    async fn revoke_label(
        &self,
        label_id: LabelId,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;
}

/// Versioned entities + membership (§8.2).
#[async_trait]
pub trait EntityStore: Send + Sync {
    /// Create an entity seeded with one address, atomically.
    async fn create_entity(
        &self,
        entity_id: EntityId,
        seed: &AccountAddress,
        evidence: &str,
        at: DateTime<Utc>,
    ) -> Result<CreateOutcome, StoreError>;

    /// Add an address to an entity's membership.
    async fn link_address(
        &self,
        entity_id: EntityId,
        address: &AccountAddress,
        evidence: &str,
        at: DateTime<Utc>,
    ) -> Result<LinkOutcome, StoreError>;

    /// An entity with its current membership, or `None` if unknown.
    async fn entity(&self, entity_id: EntityId) -> Result<Option<EntityRecord>, StoreError>;

    /// Which entity an address currently belongs to, if any.
    async fn entity_for_address(
        &self,
        address: &AccountAddress,
    ) -> Result<Option<EntityId>, StoreError>;

    /// Merge `absorbed` into `surviving` in one transaction: move membership,
    /// tombstone the absorbed entity (status + `absorbed_into`), bump **both**
    /// versions (§8.2: version increments on merge). Atomic, but *not*
    /// serialized across concurrent merges — that is the t5 actor's job.
    async fn absorb(
        &self,
        surviving: EntityId,
        absorbed: EntityId,
    ) -> Result<MergeOutcome, StoreError>;
}

/// Attribution records (§8): the mutable incident→entity overlay.
#[async_trait]
pub trait AttributionStore: Send + Sync {
    /// Upsert one attribution link, keyed `(incident_id, entity_id)` — a
    /// re-run on a redelivered `IncidentCreated` overwrites with fresher
    /// confidence/evidence.
    async fn record_attribution(&self, attribution: &AttributionRecord) -> Result<(), StoreError>;

    /// Every entity an incident is attributed to.
    async fn attributions_for_incident(
        &self,
        incident_id: IncidentId,
    ) -> Result<Vec<AttributionRecord>, StoreError>;

    /// Every incident attributed to an entity (the entity-profile read path).
    async fn attributions_for_entity(
        &self,
        entity_id: EntityId,
    ) -> Result<Vec<AttributionRecord>, StoreError>;
}

/// Sanctions lists (§8.5). The exact-address match behind the immediate
/// `SanctionHit` hard alert.
#[async_trait]
pub trait SanctionsStore: Send + Sync {
    /// Import (or refresh) list entries, keyed `(address, list_name)` — a
    /// re-import upserts in place. Returns how many rows were written.
    async fn seed_sanctions(&self, entries: &[SanctionEntry]) -> Result<u64, StoreError>;

    /// Every list designation for an address — non-empty means `SanctionHit`.
    async fn sanction_matches(
        &self,
        address: &AccountAddress,
    ) -> Result<Vec<SanctionEntry>, StoreError>;
}

/// Postgres-backed implementation of all four seams. Cheap to clone (the pool
/// is an `Arc` internally); one type because the four table groups live in one
/// database and share the pool — callers still depend only on the trait they
/// need.
#[derive(Clone)]
pub struct PgIntelligenceStore {
    pool: PgPool,
}

impl PgIntelligenceStore {
    /// Wrap a connection pool (see [`db::connect`]).
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Liveness probe for boot-time fail-fast: proves the database is
    /// reachable and the intelligence schema is applied.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query!("SELECT 1 AS one FROM labels LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(())
    }
}

// ── Raw row types ────────────────────────────────────────────────
// One struct per stored row shape, converted through `TryFrom` — the single
// boundary where database strings/floats become validated domain types, shared
// by every query over that table ("parse, don't validate").

/// A `labels` row as stored.
struct LabelRow {
    label_id: Uuid,
    address: String,
    kind: String,
    value: String,
    confidence: f64,
    source: String,
    source_detail: String,
    created_at: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
}

impl TryFrom<LabelRow> for LabelRecord {
    type Error = StoreError;

    fn try_from(row: LabelRow) -> Result<Self, StoreError> {
        Ok(LabelRecord {
            label_id: LabelId(row.label_id),
            address: parse_address_key(&row.address)?,
            kind: parse_enum(&row.kind, "label kind")?,
            value: row.value,
            confidence: parse_confidence(row.confidence)?,
            source: parse_enum(&row.source, "label source")?,
            source_detail: row.source_detail,
            created_at: row.created_at,
            valid_until: row.valid_until,
        })
    }
}

/// An `attributions` row as stored.
struct AttributionRow {
    incident_id: Uuid,
    entity_id: Uuid,
    confidence: f64,
    evidence: String,
    attributed_at: DateTime<Utc>,
}

impl TryFrom<AttributionRow> for AttributionRecord {
    type Error = StoreError;

    fn try_from(row: AttributionRow) -> Result<Self, StoreError> {
        Ok(AttributionRecord {
            incident_id: IncidentId(row.incident_id),
            entity_id: EntityId(row.entity_id),
            confidence: parse_confidence(row.confidence)?,
            evidence: row.evidence,
            attributed_at: row.attributed_at,
        })
    }
}

/// A `sanctions` row as stored.
struct SanctionRow {
    address: String,
    list_name: String,
    entry: String,
    listed_at: Option<DateTime<Utc>>,
}

impl TryFrom<SanctionRow> for SanctionEntry {
    type Error = StoreError;

    fn try_from(row: SanctionRow) -> Result<Self, StoreError> {
        Ok(SanctionEntry {
            address: parse_address_key(&row.address)?,
            list_name: row.list_name,
            entry: row.entry,
            listed_at: row.listed_at,
        })
    }
}

/// Parse a stored enum string back into `T` (strum `EnumString`).
fn parse_enum<T: FromStr>(raw: &str, what: &str) -> Result<T, StoreError> {
    raw.parse::<T>()
        .map_err(|_| StoreError::malformed(format!("{what} {raw:?} is not a known variant")))
}

/// Parse a stored confidence back into the validated newtype.
fn parse_confidence(raw: f64) -> Result<Confidence, StoreError> {
    Confidence::try_new(raw)
        .map_err(|err| StoreError::malformed(format!("stored confidence: {err}")))
}

#[async_trait]
impl LabelStore for PgIntelligenceStore {
    async fn add_label(&self, label: &LabelRecord) -> Result<bool, StoreError> {
        let result = sqlx::query!(
            "INSERT INTO labels (label_id, address, kind, value, confidence, source,
                                 source_detail, created_at, valid_until)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (label_id) DO NOTHING",
            label.label_id.0,
            address_key(&label.address),
            <&str>::from(label.kind),
            label.value,
            label.confidence.get(),
            <&str>::from(label.source),
            label.source_detail,
            label.created_at,
            label.valid_until,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn add_labels(&self, labels: &[LabelRecord]) -> Result<u64, StoreError> {
        if labels.is_empty() {
            return Ok(0);
        }
        // One UNNEST statement for the whole batch — same shape and rationale
        // as `seed_sanctions`. `ON CONFLICT DO NOTHING` (unlike `DO UPDATE`)
        // tolerates an in-slice duplicate id, so a non-deduped batch is still
        // correct, just reported coarsely (see the trait doc).
        let mut label_ids = Vec::with_capacity(labels.len());
        let mut addresses = Vec::with_capacity(labels.len());
        let mut kinds = Vec::with_capacity(labels.len());
        let mut values = Vec::with_capacity(labels.len());
        let mut confidences = Vec::with_capacity(labels.len());
        let mut sources = Vec::with_capacity(labels.len());
        let mut source_details = Vec::with_capacity(labels.len());
        let mut created_ats = Vec::with_capacity(labels.len());
        let mut valid_untils: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(labels.len());
        for label in labels {
            label_ids.push(label.label_id.0);
            addresses.push(address_key(&label.address));
            kinds.push(<&str>::from(label.kind).to_owned());
            values.push(label.value.clone());
            confidences.push(label.confidence.get());
            sources.push(<&str>::from(label.source).to_owned());
            source_details.push(label.source_detail.clone());
            created_ats.push(label.created_at);
            valid_untils.push(label.valid_until);
        }

        let result = sqlx::query!(
            r#"INSERT INTO labels (label_id, address, kind, value, confidence, source,
                                   source_detail, created_at, valid_until)
               SELECT t.label_id, t.address, t.kind, t.value, t.confidence, t.source,
                      t.source_detail, t.created_at, t.valid_until
               FROM UNNEST($1::uuid[], $2::text[], $3::text[], $4::text[], $5::float8[],
                           $6::text[], $7::text[], $8::timestamptz[], $9::timestamptz[])
                    AS t(label_id, address, kind, value, confidence, source,
                         source_detail, created_at, valid_until)
               ON CONFLICT (label_id) DO NOTHING"#,
            &label_ids,
            &addresses,
            &kinds,
            &values,
            &confidences,
            &sources,
            &source_details,
            &created_ats,
            valid_untils.as_slice() as &[Option<DateTime<Utc>>],
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn labels_for(
        &self,
        address: &AccountAddress,
        as_of: DateTime<Utc>,
    ) -> Result<Vec<LabelRecord>, StoreError> {
        let rows = sqlx::query_as!(
            LabelRow,
            r#"SELECT label_id, address, kind, value, confidence, source, source_detail,
                      created_at, valid_until
               FROM labels
               WHERE address = $1
                 AND revoked_at IS NULL
                 AND created_at <= $2
                 AND (valid_until IS NULL OR valid_until > $2)
               ORDER BY created_at, label_id"#,
            address_key(address),
            as_of,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn revoke_label(
        &self,
        label_id: LabelId,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query!(
            "UPDATE labels SET revoked_at = $2, revocation_reason = $3
             WHERE label_id = $1 AND revoked_at IS NULL",
            label_id.0,
            at,
            reason,
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}

#[async_trait]
impl EntityStore for PgIntelligenceStore {
    async fn create_entity(
        &self,
        entity_id: EntityId,
        seed: &AccountAddress,
        evidence: &str,
        at: DateTime<Utc>,
    ) -> Result<CreateOutcome, StoreError> {
        let mut tx = self.pool.begin().await?;

        let created = sqlx::query!(
            "INSERT INTO entities (entity_id, version, status, created_at)
             VALUES ($1, 1, 'active', $2)
             ON CONFLICT (entity_id) DO NOTHING",
            entity_id.0,
            at,
        )
        .execute(&mut *tx)
        .await?;
        if created.rows_affected() == 0 {
            // Redelivered create — leave the existing entity untouched.
            return Ok(CreateOutcome::AlreadyExists);
        }

        let linked = sqlx::query!(
            "INSERT INTO entity_addresses (address, entity_id, evidence, linked_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (address) DO NOTHING",
            address_key(seed),
            entity_id.0,
            evidence,
            at,
        )
        .execute(&mut *tx)
        .await?;
        if linked.rows_affected() == 0 {
            // Seed already owned elsewhere: roll the entity back (drop the tx)
            // and tell the caller who owns it — they wanted a merge.
            let owner = sqlx::query!(
                "SELECT entity_id FROM entity_addresses WHERE address = $1",
                address_key(seed),
            )
            .fetch_one(&mut *tx)
            .await?;
            return Ok(CreateOutcome::SeedOwnedBy(EntityId(owner.entity_id)));
        }

        tx.commit().await?;
        Ok(CreateOutcome::Created)
    }

    async fn link_address(
        &self,
        entity_id: EntityId,
        address: &AccountAddress,
        evidence: &str,
        at: DateTime<Utc>,
    ) -> Result<LinkOutcome, StoreError> {
        let linked = sqlx::query!(
            "INSERT INTO entity_addresses (address, entity_id, evidence, linked_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (address) DO NOTHING",
            address_key(address),
            entity_id.0,
            evidence,
            at,
        )
        .execute(&self.pool)
        .await?;
        if linked.rows_affected() == 1 {
            return Ok(LinkOutcome::Linked);
        }

        let owner = sqlx::query!(
            "SELECT entity_id FROM entity_addresses WHERE address = $1",
            address_key(address),
        )
        .fetch_one(&self.pool)
        .await?;
        if owner.entity_id == entity_id.0 {
            Ok(LinkOutcome::AlreadyMember)
        } else {
            Ok(LinkOutcome::OwnedBy(EntityId(owner.entity_id)))
        }
    }

    async fn entity(&self, entity_id: EntityId) -> Result<Option<EntityRecord>, StoreError> {
        let Some(row) = sqlx::query!(
            "SELECT entity_id, version, status, absorbed_into, created_at
             FROM entities WHERE entity_id = $1",
            entity_id.0,
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };

        let members = sqlx::query!(
            "SELECT address FROM entity_addresses
             WHERE entity_id = $1 ORDER BY linked_at, address",
            entity_id.0,
        )
        .fetch_all(&self.pool)
        .await?;

        let version = u64::try_from(row.version)
            .map_err(|_| StoreError::malformed(format!("entity version {}", row.version)))?;

        Ok(Some(EntityRecord {
            entity_id: EntityId(row.entity_id),
            version,
            status: parse_enum::<EntityStatus>(&row.status, "entity status")?,
            absorbed_into: row.absorbed_into.map(EntityId),
            addresses: members
                .into_iter()
                .map(|member| Ok(parse_address_key(&member.address)?))
                .collect::<Result<_, StoreError>>()?,
            created_at: row.created_at,
        }))
    }

    async fn entity_for_address(
        &self,
        address: &AccountAddress,
    ) -> Result<Option<EntityId>, StoreError> {
        let row = sqlx::query!(
            "SELECT entity_id FROM entity_addresses WHERE address = $1",
            address_key(address),
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| EntityId(row.entity_id)))
    }

    async fn absorb(
        &self,
        surviving: EntityId,
        absorbed: EntityId,
    ) -> Result<MergeOutcome, StoreError> {
        if surviving == absorbed {
            return Ok(MergeOutcome::SelfMerge);
        }
        let mut tx = self.pool.begin().await?;

        // Tombstone the absorbed entity first; the guard on `status = 'active'`
        // makes a redelivered merge a detectable no-op.
        let tombstoned = sqlx::query!(
            "UPDATE entities
             SET status = 'absorbed', absorbed_into = $2, version = version + 1,
                 updated_at = now()
             WHERE entity_id = $1 AND status = 'active'",
            absorbed.0,
            surviving.0,
        )
        .execute(&mut *tx)
        .await?;
        if tombstoned.rows_affected() == 0 {
            return Ok(MergeOutcome::AbsorbedInactive);
        }

        // Bump the survivor's version (§8.2) — and by RETURNING it, verify the
        // survivor is itself active; merging into a tombstone would strand the
        // moved addresses.
        let Some(survivor) = sqlx::query!(
            "UPDATE entities SET version = version + 1, updated_at = now()
             WHERE entity_id = $1 AND status = 'active'
             RETURNING version",
            surviving.0,
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            // Roll back the tombstone (drop the tx).
            return Ok(MergeOutcome::SurvivorInactive);
        };

        // Move membership. The `address` primary key stays satisfied because
        // rows only change owner.
        sqlx::query!(
            "UPDATE entity_addresses SET entity_id = $1 WHERE entity_id = $2",
            surviving.0,
            absorbed.0,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        let survivor_version = u64::try_from(survivor.version)
            .map_err(|_| StoreError::malformed(format!("entity version {}", survivor.version)))?;
        Ok(MergeOutcome::Merged { survivor_version })
    }
}

#[async_trait]
impl AttributionStore for PgIntelligenceStore {
    async fn record_attribution(&self, attribution: &AttributionRecord) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO attributions (incident_id, entity_id, confidence, evidence, attributed_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (incident_id, entity_id) DO UPDATE SET
                 confidence    = EXCLUDED.confidence,
                 evidence      = EXCLUDED.evidence,
                 attributed_at = EXCLUDED.attributed_at",
            attribution.incident_id.0,
            attribution.entity_id.0,
            attribution.confidence.get(),
            attribution.evidence,
            attribution.attributed_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn attributions_for_incident(
        &self,
        incident_id: IncidentId,
    ) -> Result<Vec<AttributionRecord>, StoreError> {
        let rows = sqlx::query_as!(
            AttributionRow,
            "SELECT incident_id, entity_id, confidence, evidence, attributed_at
             FROM attributions WHERE incident_id = $1 ORDER BY entity_id",
            incident_id.0,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn attributions_for_entity(
        &self,
        entity_id: EntityId,
    ) -> Result<Vec<AttributionRecord>, StoreError> {
        let rows = sqlx::query_as!(
            AttributionRow,
            "SELECT incident_id, entity_id, confidence, evidence, attributed_at
             FROM attributions WHERE entity_id = $1 ORDER BY attributed_at, incident_id",
            entity_id.0,
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}

#[async_trait]
impl SanctionsStore for PgIntelligenceStore {
    async fn seed_sanctions(&self, entries: &[SanctionEntry]) -> Result<u64, StoreError> {
        if entries.is_empty() {
            return Ok(0);
        }
        // Deduplicate within the batch by the upsert key (last entry wins):
        // `ON CONFLICT` cannot touch the same row twice in one statement, and
        // real feeds do contain duplicates.
        let mut by_key = std::collections::BTreeMap::new();
        for entry in entries {
            by_key.insert((address_key(&entry.address), &entry.list_name), entry);
        }

        // One UNNEST statement for the whole feed: a single round-trip and a
        // single atomic apply (a partially imported refresh would leave the
        // list in a state no feed ever published) — the OFAC SDN alone is
        // thousands of rows, so per-row round-trips are not a production path.
        let mut addresses = Vec::with_capacity(by_key.len());
        let mut list_names = Vec::with_capacity(by_key.len());
        let mut entry_names = Vec::with_capacity(by_key.len());
        let mut listed_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(by_key.len());
        for ((address, list_name), entry) in by_key {
            addresses.push(address);
            list_names.push(list_name.clone());
            entry_names.push(entry.entry.clone());
            listed_ats.push(entry.listed_at);
        }

        let result = sqlx::query!(
            r#"INSERT INTO sanctions (address, list_name, entry, listed_at, imported_at)
               SELECT t.address, t.list_name, t.entry, t.listed_at, now()
               FROM UNNEST($1::text[], $2::text[], $3::text[], $4::timestamptz[])
                    AS t(address, list_name, entry, listed_at)
               ON CONFLICT (address, list_name) DO UPDATE SET
                   entry       = EXCLUDED.entry,
                   listed_at   = EXCLUDED.listed_at,
                   imported_at = now()"#,
            &addresses,
            &list_names,
            &entry_names,
            listed_ats.as_slice() as &[Option<DateTime<Utc>>],
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn sanction_matches(
        &self,
        address: &AccountAddress,
    ) -> Result<Vec<SanctionEntry>, StoreError> {
        let rows = sqlx::query_as!(
            SanctionRow,
            "SELECT address, list_name, entry, listed_at
             FROM sanctions WHERE address = $1 ORDER BY list_name",
            address_key(address),
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retry/skip contract: I/O faults retry, our-side parse/schema bugs
    /// don't — same classification the simulation store pins.
    #[test]
    fn store_error_classifies_transient_vs_permanent() {
        assert!(StoreError::Postgres(sqlx::Error::PoolClosed).is_transient());
        assert!(StoreError::Postgres(sqlx::Error::PoolTimedOut).is_transient());

        assert!(!StoreError::Postgres(sqlx::Error::Decode("bad".into())).is_transient());
        assert!(!StoreError::Postgres(sqlx::Error::ColumnNotFound("nope".into())).is_transient());
        assert!(!StoreError::malformed("kind \"wat\"").is_transient());
    }

    #[test]
    fn parse_helpers_reject_corrupt_rows() {
        assert!(parse_enum::<crate::model::LabelKind>("wat", "label kind").is_err());
        assert!(parse_confidence(1.5).is_err());
        assert_eq!(parse_confidence(0.7).unwrap().get(), 0.7);
        // Address parsing is model::parse_address_key, folded in as Malformed.
        let err: StoreError = parse_address_key("0xnothex").unwrap_err().into();
        assert!(!err.is_transient());
    }
}
