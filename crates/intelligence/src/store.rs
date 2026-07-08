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
//! primary key) holds at every instant. Serializing the *sequence* of calls a
//! merge pass makes (read owners, decide, then several of these primitives)
//! is [`crate::merge_actor`]'s job — this store only guarantees each
//! individual call is atomic.

use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::Arc;

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
    /// `entity_id` is missing, absorbed, or split — linking into a tombstone
    /// would strand the address on a dead entity, so nothing is written. A
    /// caller that looked up `entity_id` before a concurrent merge/split can
    /// hit this even outside a race window; it should re-resolve the address's
    /// (possibly new) entity and retry, the same way `MergeOutcome::SurvivorInactive`
    /// signals the caller to re-resolve.
    TargetInactive,
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

/// What an [`EntityStore::split`] pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitOutcome {
    /// The original entity was tombstoned `Split` and one fresh entity
    /// created per group, membership moved to match.
    Split { new_ids: Vec<EntityId> },
    /// `entity_id` is missing or not active — an idempotent no-op (it was
    /// already split, absorbed, or never existed).
    NotActive,
    /// `groups` doesn't exactly partition the entity's *current* membership —
    /// a missing address, an extra one, or a duplicate across groups.
    /// Rejected; nothing written.
    Invalid,
}

/// Wallet labels with provenance (§8.1). Conflicting *claims* always coexist
/// as separate rows — never overwritten by [`add_label`](Self::add_label) —
/// but an existing row does permit two narrow, audited mutations:
/// [`revoke_label`](Self::revoke_label) (soft withdrawal) and
/// [`update_label_value`](Self::update_label_value) (an operator correcting
/// the same claim's display value in place, e.g. a typo'd tag name — distinct
/// from a *new* claim, which always mints a new coexisting row).
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

    /// One label by its id, regardless of revocation/expiry — the identity
    /// read an admin action needs before mutating a specific row (e.g.
    /// resolving the address a `label_id` belongs to before revoking it).
    /// `None` if no such label was ever stored.
    async fn label(&self, label_id: LabelId) -> Result<Option<LabelRecord>, StoreError>;

    /// Correct an existing label's `value` in place — the one narrow mutation
    /// besides revocation §8.1 permits on an already-stored row. This is
    /// deliberately *not* how a new conflicting claim is recorded (that's
    /// always [`add_label`](Self::add_label), minting a new coexisting row);
    /// it is for an operator fixing the *same* claim's display text without
    /// changing its identity or provenance. Returns the label as it stood
    /// before the correction — `None` if the id doesn't exist or is already
    /// revoked (a revoked row is frozen; rewriting a dead claim would corrupt
    /// the audit trail, not correct it).
    async fn update_label_value(
        &self,
        label_id: LabelId,
        new_value: &str,
    ) -> Result<Option<LabelRecord>, StoreError>;
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
    /// versions (§8.2: version increments on merge). Atomic, and safe against
    /// a *concurrent call to this same method* (row-locked via
    /// `lock_entities`) — but a caller that reads owners, decides a plan, and
    /// only *then* calls this needs [`crate::merge_actor`] to hold that whole
    /// sequence together; this method alone can't do that for it.
    async fn absorb(
        &self,
        surviving: EntityId,
        absorbed: EntityId,
    ) -> Result<MergeOutcome, StoreError>;

    /// Split `entity_id` back apart — the converse of [`absorb`](Self::absorb),
    /// an operator's reversal of an earlier, incorrect merge. `groups` must
    /// exactly partition the entity's *current* membership (every member in
    /// exactly one group, no outsiders); each group becomes a fresh entity,
    /// seeded/linked with the same `evidence`/`at` semantics as
    /// [`create_entity`](Self::create_entity)/[`link_address`](Self::link_address).
    /// One transaction: the original is tombstoned `Split` and every member's
    /// membership row is moved to its group's new entity atomically, so the
    /// one-entity-per-address invariant never lapses mid-split.
    async fn split(
        &self,
        entity_id: EntityId,
        groups: &[Vec<AccountAddress>],
        evidence: &str,
        at: DateTime<Utc>,
    ) -> Result<SplitOutcome, StoreError>;
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

/// The four Postgres-backed seams a pass needs, bundled so a consumer's
/// constructor doesn't take an unreadable wall of `Arc<dyn Trait>` parameters.
/// In production all four are the same [`PgIntelligenceStore`] (§14), cloned;
/// kept as separate trait objects (not one fat trait) because each is
/// independently object-safe and tested against its own in-memory double.
/// Shared by the [`attribution`](crate::attribution)'s `IncidentCreated`
/// consumer and the [`risk_scorer`](crate::risk_scorer)'s cache-invalidation
/// consumer (§8.3) — both need every store the risk kernel and the
/// association flywheel read from. `Clone` is cheap (every field is an
/// `Arc<dyn Trait>` bump) — the risk-scoring consumer clones its seams into
/// each bounded-concurrency recompute task.
#[derive(Clone)]
pub struct StoreSeams {
    pub labels: Arc<dyn LabelStore>,
    pub entities: Arc<dyn EntityStore>,
    pub attributions: Arc<dyn AttributionStore>,
    pub sanctions: Arc<dyn SanctionsStore>,
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

    async fn label(&self, label_id: LabelId) -> Result<Option<LabelRecord>, StoreError> {
        let Some(row) = sqlx::query_as!(
            LabelRow,
            "SELECT label_id, address, kind, value, confidence, source, source_detail,
                    created_at, valid_until
             FROM labels WHERE label_id = $1",
            label_id.0,
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        Ok(Some(row.try_into()?))
    }

    async fn update_label_value(
        &self,
        label_id: LabelId,
        new_value: &str,
    ) -> Result<Option<LabelRecord>, StoreError> {
        let mut tx = self.pool.begin().await?;

        // Read-then-write inside one transaction so the returned "before"
        // value is exactly what the UPDATE below replaces, even under
        // concurrent correction attempts.
        let Some(before) = sqlx::query_as!(
            LabelRow,
            "SELECT label_id, address, kind, value, confidence, source, source_detail,
                    created_at, valid_until
             FROM labels WHERE label_id = $1 AND revoked_at IS NULL
             FOR UPDATE",
            label_id.0,
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };

        sqlx::query!(
            "UPDATE labels SET value = $2 WHERE label_id = $1",
            label_id.0,
            new_value,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(before.try_into()?))
    }
}

/// Lock the given entity rows for the rest of the transaction, in ascending
/// `entity_id` order — the deadlock-safe protocol every membership-mutating
/// method (`link_address`, `absorb`, `split`) uses to serialize against each
/// other *per entity*.
///
/// Without this, two concurrent writers can race a read-then-write window:
/// e.g. `split` reads an entity's current membership, then a concurrent
/// `link_address` adds a new address to that same entity before `split`
/// tombstones it — the new address is left pointing at a tombstoned entity,
/// a dangling membership row. Locking the entity row up front (before any
/// membership read) closes that window: the second transaction simply blocks
/// until the first commits, then sees the post-commit truth.
///
/// Always lock in one fixed order (ascending `Uuid`) regardless of the
/// caller's argument order — `absorb(a, b)` running concurrently with
/// `absorb(b, a)` (or `split`/`link_address` on the same pair) must acquire
/// the same two locks in the same order, or Postgres detects a deadlock and
/// aborts one side. Sorting here is what makes every call site deadlock-safe
/// without each one having to reason about lock order itself.
async fn lock_entities(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entity_ids: &[EntityId],
) -> Result<(), StoreError> {
    let mut ids: Vec<Uuid> = entity_ids.iter().map(|id| id.0).collect();
    ids.sort();
    ids.dedup();
    sqlx::query!(
        "SELECT entity_id FROM entities WHERE entity_id = ANY($1::uuid[])
         ORDER BY entity_id FOR UPDATE",
        &ids,
    )
    .fetch_all(&mut **tx)
    .await?;
    Ok(())
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
        let mut tx = self.pool.begin().await?;
        // Serialize against a concurrent `absorb`/`split` of this same entity —
        // see `lock_entities`'s docs for the race this closes.
        lock_entities(&mut tx, &[entity_id]).await?;

        // Refuse to link into a tombstone — not just the concurrent case (the
        // lock above), but a caller that resolved `entity_id` before an
        // already-committed merge/split too. Either way, linking here would
        // strand the address on a dead entity.
        let is_active = sqlx::query!(
            "SELECT 1 AS one FROM entities WHERE entity_id = $1 AND status = 'active'",
            entity_id.0,
        )
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if !is_active {
            return Ok(LinkOutcome::TargetInactive);
        }

        let linked = sqlx::query!(
            "INSERT INTO entity_addresses (address, entity_id, evidence, linked_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (address) DO NOTHING",
            address_key(address),
            entity_id.0,
            evidence,
            at,
        )
        .execute(&mut *tx)
        .await?;
        if linked.rows_affected() == 1 {
            tx.commit().await?;
            return Ok(LinkOutcome::Linked);
        }

        let owner = sqlx::query!(
            "SELECT entity_id FROM entity_addresses WHERE address = $1",
            address_key(address),
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
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
        // Serialize against a concurrent `link_address`/`absorb`/`split` on
        // either entity — locked in a fixed order so a concurrent `absorb`
        // running the opposite direction can't deadlock against this one.
        lock_entities(&mut tx, &[surviving, absorbed]).await?;

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

    async fn split(
        &self,
        entity_id: EntityId,
        groups: &[Vec<AccountAddress>],
        evidence: &str,
        at: DateTime<Utc>,
    ) -> Result<SplitOutcome, StoreError> {
        let mut tx = self.pool.begin().await?;
        // Serialize against a concurrent `link_address`/`absorb`/`split` on
        // this entity — locked *before* reading membership below, which is
        // what closes the read-then-write race: without this, a concurrent
        // `link_address` could add a member between the membership read and
        // the tombstone write, leaving it pointing at a tombstoned entity.
        lock_entities(&mut tx, &[entity_id]).await?;

        let is_active = sqlx::query!(
            "SELECT 1 AS one FROM entities WHERE entity_id = $1 AND status = 'active'",
            entity_id.0,
        )
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if !is_active {
            return Ok(SplitOutcome::NotActive);
        }

        // `groups` must exactly partition the entity's *current* membership —
        // validated before any write, so an invalid request touches nothing.
        // Safe from a TOCTOU race now: the lock above holds until commit.
        let current: BTreeSet<String> = sqlx::query!(
            "SELECT address FROM entity_addresses WHERE entity_id = $1",
            entity_id.0,
        )
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|row| row.address)
        .collect();

        let mut proposed: BTreeSet<String> = BTreeSet::new();
        for group in groups {
            if group.is_empty() {
                return Ok(SplitOutcome::Invalid);
            }
            for address in group {
                if !proposed.insert(address_key(address)) {
                    // A duplicate address, within one group or across two.
                    return Ok(SplitOutcome::Invalid);
                }
            }
        }
        if proposed != current {
            return Ok(SplitOutcome::Invalid);
        }

        // Tombstone the original — guarded by `status = 'active'` again so a
        // concurrent split/absorb since the check above can't double-split.
        let tombstoned = sqlx::query!(
            "UPDATE entities SET status = 'split', version = version + 1, updated_at = now()
             WHERE entity_id = $1 AND status = 'active'",
            entity_id.0,
        )
        .execute(&mut *tx)
        .await?;
        if tombstoned.rows_affected() == 0 {
            return Ok(SplitOutcome::NotActive);
        }

        // One fresh entity per group, membership moved to match.
        let mut new_ids = Vec::with_capacity(groups.len());
        for group in groups {
            let new_id = EntityId::new();
            sqlx::query!(
                "INSERT INTO entities (entity_id, version, status, created_at)
                 VALUES ($1, 1, 'active', $2)",
                new_id.0,
                at,
            )
            .execute(&mut *tx)
            .await?;

            let addresses: Vec<String> = group.iter().map(address_key).collect();
            sqlx::query!(
                "UPDATE entity_addresses SET entity_id = $1, evidence = $2, linked_at = $3
                 WHERE address = ANY($4::text[])",
                new_id.0,
                evidence,
                at,
                &addresses,
            )
            .execute(&mut *tx)
            .await?;

            new_ids.push(new_id);
        }

        tx.commit().await?;
        Ok(SplitOutcome::Split { new_ids })
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

    // ── `label`/`update_label_value`/`split`, over the in-memory double ──
    // These three are pure CRUD (no cluster.rs-style pure-decision module of
    // their own), so their contract is pinned here against `test_util`'s
    // double — the real Postgres semantics are proven by the `#[ignore]`
    // integration tests in `tests/stores.rs`.

    use crate::model::{LabelKind, LabelSource};
    use crate::test_util::InMemoryIntelligenceStore;
    use alloy_primitives::Address;

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    #[tokio::test]
    async fn label_finds_a_stored_row_regardless_of_revocation_and_none_for_unknown() {
        let store = InMemoryIntelligenceStore::new();
        let label = LabelRecord::new(
            addr(1),
            LabelKind::CexWallet,
            "Binance 14",
            LabelSource::Manual,
            "operator",
            at(1),
        );
        store.add_label(&label).await.unwrap();

        assert_eq!(
            store.label(label.label_id).await.unwrap(),
            Some(label.clone())
        );
        assert_eq!(store.label(LabelId::new()).await.unwrap(), None);

        store
            .revoke_label(label.label_id, "wrong", at(2))
            .await
            .unwrap();
        assert_eq!(
            store.label(label.label_id).await.unwrap(),
            Some(label),
            "label() ignores revocation — it's the identity read, not the active-set read"
        );
    }

    #[tokio::test]
    async fn update_label_value_corrects_in_place_and_reports_the_old_value() {
        let store = InMemoryIntelligenceStore::new();
        let label = LabelRecord::new(
            addr(1),
            LabelKind::CexWallet,
            "Binance 14 (typo)",
            LabelSource::Manual,
            "operator",
            at(1),
        );
        store.add_label(&label).await.unwrap();

        let before = store
            .update_label_value(label.label_id, "Binance 14")
            .await
            .unwrap()
            .expect("label exists");
        assert_eq!(before.value, "Binance 14 (typo)");

        let labels = store.labels_for(&addr(1), at(1_000)).await.unwrap();
        assert_eq!(
            labels.len(),
            1,
            "corrected in place, not a new coexisting row"
        );
        assert_eq!(labels[0].value, "Binance 14");
        assert_eq!(labels[0].label_id, label.label_id, "identity is unchanged");
    }

    #[tokio::test]
    async fn update_label_value_refuses_a_revoked_or_unknown_label() {
        let store = InMemoryIntelligenceStore::new();
        let label = LabelRecord::new(
            addr(1),
            LabelKind::CexWallet,
            "Binance 14",
            LabelSource::Manual,
            "operator",
            at(1),
        );
        store.add_label(&label).await.unwrap();
        store
            .revoke_label(label.label_id, "wrong", at(2))
            .await
            .unwrap();

        assert_eq!(
            store
                .update_label_value(label.label_id, "new value")
                .await
                .unwrap(),
            None,
            "a revoked row is frozen — correcting it would corrupt the audit trail"
        );
        assert_eq!(
            store
                .update_label_value(LabelId::new(), "new value")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn split_partitions_membership_into_fresh_entities() {
        let store = InMemoryIntelligenceStore::new();
        let entity_id = EntityId::new();
        store
            .create_entity(entity_id, &addr(1), "seed", at(1))
            .await
            .unwrap();
        store
            .link_address(entity_id, &addr(2), "cluster", at(1))
            .await
            .unwrap();
        store
            .link_address(entity_id, &addr(3), "cluster", at(1))
            .await
            .unwrap();

        let groups = vec![vec![addr(1), addr(2)], vec![addr(3)]];
        let SplitOutcome::Split { new_ids } = store
            .split(entity_id, &groups, "operator:kkt", at(10))
            .await
            .unwrap()
        else {
            panic!("expected a successful split");
        };
        assert_eq!(new_ids.len(), 2);
        assert_ne!(new_ids[0], new_ids[1]);

        // The original is tombstoned and owns nothing.
        assert_eq!(
            store.entity(entity_id).await.unwrap().unwrap().status,
            EntityStatus::Split
        );
        assert_eq!(
            store.entity_for_address(&addr(1)).await.unwrap(),
            Some(new_ids[0])
        );
        assert_eq!(
            store.entity_for_address(&addr(2)).await.unwrap(),
            Some(new_ids[0])
        );
        assert_eq!(
            store.entity_for_address(&addr(3)).await.unwrap(),
            Some(new_ids[1])
        );

        // Re-running the same split against the now-tombstoned original is a
        // no-op, not a second split — idempotent under redelivery/retry.
        assert_eq!(
            store
                .split(entity_id, &groups, "operator:kkt", at(20))
                .await
                .unwrap(),
            SplitOutcome::NotActive
        );

        // A caller that resolved `entity_id` before the split (e.g. a stale
        // cluster-walk result) must not be able to strand a new member on the
        // now-dead entity.
        assert_eq!(
            store
                .link_address(entity_id, &addr(4), "late cluster signal", at(30))
                .await
                .unwrap(),
            LinkOutcome::TargetInactive
        );
    }

    #[tokio::test]
    async fn link_address_refuses_an_absorbed_target_too() {
        let store = InMemoryIntelligenceStore::new();
        let (survivor, absorbed) = (EntityId::new(), EntityId::new());
        store
            .create_entity(survivor, &addr(1), "seed", at(1))
            .await
            .unwrap();
        store
            .create_entity(absorbed, &addr(2), "seed", at(1))
            .await
            .unwrap();
        store.absorb(survivor, absorbed).await.unwrap();

        assert_eq!(
            store
                .link_address(absorbed, &addr(3), "stale target", at(10))
                .await
                .unwrap(),
            LinkOutcome::TargetInactive,
            "absorbed is a tombstone now — linking into it would strand addr(3)"
        );
        // The survivor is still a perfectly valid target.
        assert_eq!(
            store
                .link_address(survivor, &addr(3), "correct target", at(10))
                .await
                .unwrap(),
            LinkOutcome::Linked
        );
    }

    #[tokio::test]
    async fn split_rejects_a_partition_that_does_not_match_current_membership() {
        let store = InMemoryIntelligenceStore::new();
        let entity_id = EntityId::new();
        store
            .create_entity(entity_id, &addr(1), "seed", at(1))
            .await
            .unwrap();
        store
            .link_address(entity_id, &addr(2), "cluster", at(1))
            .await
            .unwrap();

        // Missing addr(2).
        assert_eq!(
            store
                .split(entity_id, &[vec![addr(1)]], "op", at(10))
                .await
                .unwrap(),
            SplitOutcome::Invalid
        );
        // An outsider that never belonged to this entity.
        assert_eq!(
            store
                .split(entity_id, &[vec![addr(1), addr(2), addr(9)]], "op", at(10))
                .await
                .unwrap(),
            SplitOutcome::Invalid
        );
        // The same address in two groups.
        assert_eq!(
            store
                .split(
                    entity_id,
                    &[vec![addr(1), addr(2)], vec![addr(2)]],
                    "op",
                    at(10)
                )
                .await
                .unwrap(),
            SplitOutcome::Invalid
        );
        // Membership must be intact after every rejected attempt.
        assert_eq!(
            store.entity(entity_id).await.unwrap().unwrap().status,
            EntityStatus::Active
        );
    }

    #[tokio::test]
    async fn split_on_a_missing_or_already_split_entity_is_not_active() {
        let store = InMemoryIntelligenceStore::new();
        assert_eq!(
            store
                .split(EntityId::new(), &[vec![addr(1)]], "op", at(10))
                .await
                .unwrap(),
            SplitOutcome::NotActive
        );
    }
}
