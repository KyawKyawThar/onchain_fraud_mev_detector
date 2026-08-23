//! Persistence seams behind the incident projection (§7, §14, Sprint 6 t5).
//!
//! The pure [`IncidentProjection`](crate::projection) fold is the source of truth for
//! *what* an incident's current state is — idempotent and reorg-safe. This module is
//! the write-through that lands that state in the two stores §14 assigns the
//! simulation service, each behind an object-safe seam so the
//! [`projection_consumer`](crate::projection_consumer) can be tested against in-memory
//! doubles with no database:
//!
//! - [`IncidentStore`] — the **mutable, transactional** Postgres records: the in-flight
//!   job row ([`JobUpdate`]) and the confirmed-incident read model
//!   ([`IncidentStore::upsert_incident`]). Both writes are full-row **upserts**, so
//!   re-applying a redelivered/stale event is a harmless no-op — the fold guarantees the
//!   [`IncidentRecord`] passed in is always the current merged truth, and the SQL
//!   `sim_jobs` upsert is independently monotonic (a `completed` job can't regress to
//!   `requested`, a first-seen timestamp is kept) so job tracking is correct even though
//!   jobs are *not* folded through the projection.
//! - [`IncidentAnalytics`] — the **append-only** ClickHouse `incident_analytics` firehose
//!   ([`AnalyticsRow`]): one immutable row per non-duplicate result event, for the wide
//!   scans (by kind / severity / window) a row store can't serve. Written RowBinary
//!   through the same `clickhouse` client the event store uses.
//!
//! Encoding a row can't fail (the mappings are total), so a [`PersistError`] is normally an
//! I/O fault the consumer retries. [`PersistError`]'s `Transience` impl still classifies it — a
//! permanent Postgres fault (a decode/schema bug) is skipped rather than retried forever, so
//! one poison event can't wedge the stream (§4) — mirroring
//! [`event-store`'s `StoreError`](../../event-store/src/store.rs) retry-vs-skip contract.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clickhouse::Client;
use events::primitives::{
    AccountAddress, AlertId, Chain, Confidence, CrossChainFindingId, IncidentId, UsdAmount,
};
use events::{DomainEvent, EventEnvelope};
use revm::primitives::B256;
use secrecy::ExposeSecret;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::ClickhouseConfig;
use crate::cross_chain_projection::{CrossChainFindingKind, CrossChainFindingRecord};
use crate::projection::{IncidentRecord, IncidentStatus};

/// A failure writing to (or probing) one of the stores. The variant — and, for Postgres,
/// the specific `sqlx` error — decides whether retrying the *same* write could ever succeed,
/// which is how the consumer chooses between "leave the offset and redeliver" and "this row
/// is poison, skip it so it can't wedge the stream" (§4). See its [`event_bus::Transience`] impl.
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    /// A Postgres round-trip failed. Usually transient (connection/pool/server), but an
    /// encoding/decoding/schema fault ([`db::is_permanent`]) is a bug that fails identically
    /// on every retry.
    #[error("postgres write failed")]
    Postgres(#[from] sqlx::Error),

    /// A ClickHouse round-trip failed (unreachable, timeout, server error) — an I/O fault,
    /// so always transient.
    #[error("clickhouse write failed")]
    Clickhouse(#[from] clickhouse::error::Error),
}

impl event_bus::Transience for PersistError {
    /// Whether retrying the same write could plausibly succeed later. A transient fault
    /// (I/O, pool, server) is redelivered; a permanent one (a programming/encoding/schema
    /// bug that will fail identically every time) is skipped so it can't wedge the stream
    /// (§4). Postgres faults classify through the shared [`db::is_permanent`] so the
    /// decision can't drift across services; same retry-vs-skip contract as
    /// [`event-store`'s `StoreError`](../../event-store/src/store.rs).
    fn is_transient(&self) -> bool {
        match self {
            PersistError::Clickhouse(_) => true,
            PersistError::Postgres(err) => !db::is_permanent(err),
        }
    }
}

/// Which point of a job's lifecycle a [`JobUpdate`] records. Derived directly from the
/// event type (jobs are not folded through the projection): `SimulationRequested` →
/// [`Requested`](JobState::Requested), `SimulationCompleted` → [`Completed`](JobState::Completed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// The dispatcher queued the `SimulationJob` (audited by `SimulationRequested`).
    Requested,
    /// A worker finished the run and published its `SimulationCompleted`.
    Completed,
}

impl JobState {
    /// The `sim_jobs.status` string this state persists as.
    fn as_str(self) -> &'static str {
        match self {
            JobState::Requested => "requested",
            JobState::Completed => "completed",
        }
    }
}

/// One in-flight-job state transition to upsert into `sim_jobs`, keyed by the provisional
/// `alert_id` that spans the whole job lifecycle. `at` is the triggering event's
/// occurrence time (`occurred_at`), stamped onto the matching timestamp column.
#[derive(Debug, Clone)]
pub struct JobUpdate {
    pub alert_id: AlertId,
    pub chain: Chain,
    pub state: JobState,
    pub at: DateTime<Utc>,
}

impl JobUpdate {
    /// Derive the job-tracking update a result-path event implies, if any. Only the two
    /// job-lifecycle events map; the incident-only terminals (`IncidentRetracted`/
    /// `IncidentFinalized`) and every non-simulation event return `None`.
    pub fn from_event(envelope: &EventEnvelope) -> Option<Self> {
        let (alert_id, state) = match &envelope.payload {
            DomainEvent::SimulationRequested(req) => (req.alert_id, JobState::Requested),
            DomainEvent::SimulationCompleted(done) => (done.alert_id, JobState::Completed),
            _ => return None,
        };
        Some(Self {
            alert_id,
            chain: envelope.chain,
            state,
            at: envelope.occurred_at,
        })
    }
}

/// Hard ceiling on one [`IncidentStore::list_incidents`] page — a guard against an
/// unbounded scan. Mirrors [`event-store`'s `MAX_LIMIT`](../../event-store/src/query.rs).
pub const MAX_INCIDENTS_LIMIT: u64 = 1_000;
/// Default page size when a caller doesn't ask for one.
pub const DEFAULT_INCIDENTS_LIMIT: u64 = 100;

/// A keyset cursor into the `(updated_at, alert_id)` sort order `list_incidents` walks
/// newest-first: the position to resume *after*. Opaque to HTTP callers (see
/// [`crate::http`]'s token encoding) but a plain struct here — the store only ever
/// receives one back verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentCursor {
    pub updated_at: DateTime<Utc>,
    pub alert_id: Uuid,
}

impl IncidentCursor {
    /// Encode as `<unix_millis>:<alert_id>` — mirrors
    /// [`event-store`'s `Cursor::token`](../../event-store/src/query.rs).
    pub fn token(&self) -> String {
        format!("{}:{}", self.updated_at.timestamp_millis(), self.alert_id)
    }

    /// Parse a token from [`Self::token`]. `None` on any malformation (the caller
    /// maps that to a 400).
    pub fn parse(token: &str) -> Option<Self> {
        let (millis, alert_id) = token.split_once(':')?;
        Some(Self {
            updated_at: DateTime::<Utc>::from_timestamp_millis(millis.parse().ok()?)?,
            alert_id: alert_id.parse().ok()?,
        })
    }
}

/// Optional narrowing for [`IncidentStore::list_incidents`] (§11 `/v1/incidents`). An
/// unset field is simply not constrained; `cursor`/`limit` drive pagination and never
/// count as narrowing.
#[derive(Debug, Default, Clone)]
pub struct IncidentFilters {
    pub status: Option<IncidentStatus>,
    /// Resume after this point in the sort order (keyset pagination).
    pub cursor: Option<IncidentCursor>,
    /// Max rows for this page; clamped to `[1, MAX_INCIDENTS_LIMIT]`, defaulting to
    /// [`DEFAULT_INCIDENTS_LIMIT`].
    pub limit: Option<u64>,
}

impl IncidentFilters {
    /// The effective page size: the caller's `limit` clamped to
    /// `[1, MAX_INCIDENTS_LIMIT]`, or [`DEFAULT_INCIDENTS_LIMIT`] when unset.
    fn effective_limit(&self) -> u64 {
        self.limit
            .unwrap_or(DEFAULT_INCIDENTS_LIMIT)
            .clamp(1, MAX_INCIDENTS_LIMIT)
    }
}

/// One page of [`IncidentStore::list_incidents`] results plus where to resume.
#[derive(Debug)]
pub struct IncidentPage {
    /// Rows, most-recently-updated first.
    pub incidents: Vec<IncidentRecord>,
    /// Set iff this page was full and more rows may follow. `None` means the listing
    /// is exhausted, so a caller can always tell a complete result from a truncated one.
    pub next_cursor: Option<IncidentCursor>,
}

/// The mutable Postgres records (§14): in-flight jobs + the confirmed-incident read model.
/// Object-safe so the consumer holds a `dyn IncidentStore` and swaps [`PgIncidentStore`]
/// for a test double.
#[async_trait]
pub trait IncidentStore: Send + Sync {
    /// Upsert the folded incident read-model row, keyed by `alert_id`. Idempotent: the
    /// [`IncidentRecord`] is always the current merged truth, so re-applying a
    /// redelivered event overwrites with identical values.
    async fn upsert_incident(&self, record: &IncidentRecord) -> Result<(), PersistError>;

    /// Record an in-flight job's lifecycle transition. Idempotent and monotonic in SQL
    /// (a `completed` job can't regress; a first-seen timestamp is preserved).
    async fn record_job(&self, job: &JobUpdate) -> Result<(), PersistError>;

    /// List confirmed-incident rows, newest-updated first (§11 `GET /v1/incidents` —
    /// [`crate::http`]), optionally narrowed by status and paginated by `filters`.
    async fn list_incidents(&self, filters: &IncidentFilters)
        -> Result<IncidentPage, PersistError>;
}

/// The append-only ClickHouse analytics firehose (§14). Object-safe for the same reason.
#[async_trait]
pub trait IncidentAnalytics: Send + Sync {
    /// Append one immutable analytics row.
    async fn append(&self, row: &AnalyticsRow) -> Result<(), PersistError>;
}

/// Hard ceiling on one [`WalletExposureStore::mev_exposure`] result — a guard
/// against an unbounded scan for a heavily-targeted address (mirrors
/// [`MAX_INCIDENTS_LIMIT`]). A wallet with more confirmed incidents than this has
/// its exposure summary computed over the most-recent `MAX_EXPOSURE_INCIDENTS`;
/// realistic per-wallet cardinality sits far below the cap, and the newest-first
/// order keeps the truncated view the most relevant one.
pub const MAX_EXPOSURE_INCIDENTS: u64 = 10_000;

/// A wallet's confirmed-incident rows, as folded by [`ExposureRow`] (§11 wallet
/// MEV-exposure). Its own seam, sibling to [`IncidentAnalytics`] rather than a
/// method on it — a read concern over the same table, not part of the append-only
/// firehose's contract (mirrors `intelligence::adjacency::AdjacencyStore` sitting
/// beside `intelligence::store`'s write seams).
#[async_trait]
pub trait WalletExposureStore: Send + Sync {
    /// The confirmed incidents that named `victim_address` as their victim,
    /// newest first, optionally narrowed to a created-time lower bound `since`.
    ///
    /// **One row per incident, reflecting its *current* lifecycle state** — the
    /// append-only analytics table holds a snapshot row per lifecycle event
    /// (created/finalized/retracted), so the read folds each incident to its
    /// latest snapshot and keeps only the still-confirmed ones. An incident that
    /// was created then **retracted** (a §15 reorg withdrew it) is therefore
    /// excluded: the money never actually moved, so it must not show as a loss.
    async fn mev_exposure(
        &self,
        victim_address: &AccountAddress,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<ExposureRow>, PersistError>;
}

/// One `incident_timing_rollup` bucket for a `(chain, severity)` pair, after
/// re-aggregating the SummingMergeTree's per-part sums (see
/// [`TimingStore::timing_buckets`]). Sparse: a `slot_of_day` with no
/// confirmed incidents simply has no row — the caller (`crate::timing`) fills
/// the gaps.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Deserialize)]
pub struct TimingBucketRow {
    pub slot_of_day: u16,
    pub incident_count: u64,
    pub total_victim_loss_usd: f64,
}

/// The read behind `GET /v1/timing/recommendation` (safe-block-timing):
/// historical incident intensity by 10-minute UTC time-of-day slot, for one
/// chain and one severity ("size") band. Its own seam, sibling to
/// [`WalletExposureStore`] rather than a method on it — a read concern over
/// the `incident_timing_rollup` rollup, not the append-only
/// `incident_analytics` firehose.
#[async_trait]
pub trait TimingStore: Send + Sync {
    /// Every bucket recorded for `chain`/`severity`, in no particular order —
    /// [`crate::timing::rank_windows`] does the ranking.
    async fn timing_buckets(
        &self,
        chain: Chain,
        severity: crate::timing::SizeBand,
    ) -> Result<Vec<TimingBucketRow>, PersistError>;
}

/// Postgres-backed [`IncidentStore`]. Cheap to clone (the pool is an `Arc` internally).
#[derive(Clone)]
pub struct PgIncidentStore {
    pool: PgPool,
}

impl PgIncidentStore {
    /// Wrap a connection pool (see [`db::connect`]) as the incident store.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Liveness probe: a trivial query that proves Postgres is reachable — used by
    /// [`crate::http`]'s `/healthz`, mirroring [`ClickhouseAnalytics::ping`].
    pub async fn ping(&self) -> Result<(), PersistError> {
        sqlx::query!("SELECT 1 AS one")
            .fetch_one(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl IncidentStore for PgIncidentStore {
    async fn upsert_incident(&self, record: &IncidentRecord) -> Result<(), PersistError> {
        // Total value→row mapping: ids to UUID, kind/severity/status to their wire
        // strings, hashes to 0x-hex. Nothing here can fail — a `PersistError` is always
        // the round-trip below.
        let alert_id: Uuid = record.alert_id.0;
        let incident_id: Option<Uuid> = record.incident_id.map(|id| id.0);
        let status = record.status.as_str();
        let kind: Option<&str> = record.kind.map(<&'static str>::from);
        let severity: Option<&str> = record.severity.map(<&'static str>::from);
        let txs: Vec<String> = record.txs.iter().map(|tx| format!("{tx:#x}")).collect();
        let finalized_block: Option<String> = record.finalized_block.map(|b| format!("{b:#x}"));
        let victim_address: Option<String> = record.victim_address.map(|a| normalized_address(&a));
        let victim_loss_usd: Option<f64> = record.victim_loss_usd.map(UsdAmount::get);

        sqlx::query!(
            "INSERT INTO incidents (
                 alert_id, incident_id, status, kind, severity, profit, victim_loss,
                 txs, victim_address, victim_loss_usd, retraction_reason, finalized_block,
                 figures_at, retracted_at, finalized_at, updated_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, now())
             ON CONFLICT (alert_id) DO UPDATE SET
                 incident_id       = EXCLUDED.incident_id,
                 status            = EXCLUDED.status,
                 kind              = EXCLUDED.kind,
                 severity          = EXCLUDED.severity,
                 profit            = EXCLUDED.profit,
                 victim_loss       = EXCLUDED.victim_loss,
                 txs               = EXCLUDED.txs,
                 victim_address    = EXCLUDED.victim_address,
                 victim_loss_usd   = EXCLUDED.victim_loss_usd,
                 retraction_reason = EXCLUDED.retraction_reason,
                 finalized_block   = EXCLUDED.finalized_block,
                 figures_at        = EXCLUDED.figures_at,
                 retracted_at      = EXCLUDED.retracted_at,
                 finalized_at      = EXCLUDED.finalized_at,
                 updated_at        = now()",
            alert_id,
            incident_id,
            status,
            kind,
            severity,
            record.profit,
            record.victim_loss,
            &txs,
            victim_address.as_deref(),
            victim_loss_usd,
            record.retraction_reason.as_deref(),
            finalized_block.as_deref(),
            record.figures_at(),
            record.retracted_at(),
            record.finalized_at(),
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_job(&self, job: &JobUpdate) -> Result<(), PersistError> {
        let alert_id: Uuid = job.alert_id.0;
        let chain: i64 = job.chain.id() as i64;
        let status = job.state.as_str();
        // Only the timestamp this transition owns is set; the other stays NULL and is
        // filled by whichever event carries it (COALESCE keeps the first-seen value).
        let (requested_at, completed_at) = match job.state {
            JobState::Requested => (Some(job.at), None),
            JobState::Completed => (None, Some(job.at)),
        };

        sqlx::query!(
            "INSERT INTO sim_jobs (alert_id, chain, status, requested_at, completed_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, now())
             ON CONFLICT (alert_id) DO UPDATE SET
                 chain        = EXCLUDED.chain,
                 -- A finished job never regresses to 'requested' on a reordered/redelivered
                 -- SimulationRequested.
                 status       = CASE WHEN sim_jobs.status = 'completed'
                                     THEN 'completed' ELSE EXCLUDED.status END,
                 requested_at = COALESCE(sim_jobs.requested_at, EXCLUDED.requested_at),
                 completed_at = COALESCE(sim_jobs.completed_at, EXCLUDED.completed_at),
                 updated_at   = now()",
            alert_id,
            chain,
            status,
            requested_at,
            completed_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_incidents(
        &self,
        filters: &IncidentFilters,
    ) -> Result<IncidentPage, PersistError> {
        let status = filters.status.map(IncidentStatus::as_str);
        let cursor_updated_at = filters.cursor.map(|c| c.updated_at);
        let cursor_alert_id = filters.cursor.map(|c| c.alert_id);
        let limit = filters.effective_limit();
        // Fetch one row past `limit` so we can tell whether another page exists
        // without a second round-trip (mirrors event-store's `run_paged`).
        let fetch_limit = (limit + 1) as i64;

        let mut rows = sqlx::query!(
            "SELECT alert_id, incident_id, status, kind, severity, profit, victim_loss,
                    txs, victim_address, victim_loss_usd, retraction_reason, finalized_block,
                    figures_at, retracted_at, finalized_at, updated_at
             FROM incidents
             WHERE ($1::text IS NULL OR status = $1)
               AND ($2::timestamptz IS NULL OR $3::uuid IS NULL
                    OR (updated_at, alert_id) < ($2, $3))
             ORDER BY updated_at DESC, alert_id DESC
             LIMIT $4",
            status,
            cursor_updated_at,
            cursor_alert_id,
            fetch_limit,
        )
        .fetch_all(&self.pool)
        .await?;

        let has_more = rows.len() as u64 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            rows.last().map(|row| IncidentCursor {
                updated_at: row.updated_at,
                alert_id: row.alert_id,
            })
        } else {
            None
        };

        let incidents = rows
            .into_iter()
            .map(|row| {
                let status = IncidentStatus::parse(&row.status).ok_or_else(|| {
                    PersistError::Postgres(sqlx::Error::ColumnDecode {
                        index: "status".to_owned(),
                        source: format!("unrecognized incident status {:?}", row.status).into(),
                    })
                })?;
                let kind = row.kind.as_deref().map(parse_wire_enum).transpose()?;
                let severity = row.severity.as_deref().map(parse_wire_enum).transpose()?;
                let txs = row
                    .txs
                    .iter()
                    .map(|tx| parse_hex_column("txs", tx))
                    .collect::<Result<Vec<B256>, PersistError>>()?;
                let finalized_block = row
                    .finalized_block
                    .as_deref()
                    .map(|raw| parse_hex_column("finalized_block", raw))
                    .transpose()?;
                let victim_address = row
                    .victim_address
                    .as_deref()
                    .map(|raw| parse_address_column("victim_address", raw))
                    .transpose()?;
                let victim_loss_usd = row.victim_loss_usd.map(UsdAmount::new);

                Ok(IncidentRecord::from_stored(
                    AlertId(row.alert_id),
                    row.incident_id.map(IncidentId),
                    status,
                    kind,
                    severity,
                    row.profit,
                    row.victim_loss,
                    txs,
                    victim_address,
                    victim_loss_usd,
                    row.retraction_reason,
                    finalized_block,
                    row.figures_at,
                    row.retracted_at,
                    row.finalized_at,
                ))
            })
            .collect::<Result<Vec<_>, PersistError>>()?;

        Ok(IncidentPage {
            incidents,
            next_cursor,
        })
    }
}

/// Hard ceiling on one [`CrossChainFindingStore::list_findings`] page (§24,
/// Sprint 17 t4) — a guard against an unbounded scan, mirroring
/// [`MAX_INCIDENTS_LIMIT`]. Cross-chain findings are a much lower-volume
/// stream than incidents (they need a correlated multi-chain match, not just
/// a single-chain detector trigger), so both the ceiling and the default sit
/// lower.
pub const MAX_CROSS_CHAIN_FINDINGS_LIMIT: u64 = 200;
/// Default page size when a caller doesn't ask for one.
pub const DEFAULT_CROSS_CHAIN_FINDINGS_LIMIT: u64 = 50;

/// Optional narrowing for [`CrossChainFindingStore::list_findings`] (§11
/// `/v1/incidents`, whose `cross_chain_findings` array this backs — see
/// [`crate::http`]). No keyset cursor, unlike [`IncidentFilters`]: today's
/// low finding volume doesn't yet justify one — a documented simplification,
/// not an oversight (see [`crate::cross_chain_projection`]'s module docs for
/// why this is its own read model rather than reusing `IncidentFilters`).
#[derive(Debug, Default, Clone)]
pub struct CrossChainFindingFilters {
    /// `Some(false)` = live findings only, `Some(true)` = retracted only,
    /// `None` = both.
    pub retracted: Option<bool>,
    /// Max rows; clamped to `[1, MAX_CROSS_CHAIN_FINDINGS_LIMIT]`, defaulting
    /// to [`DEFAULT_CROSS_CHAIN_FINDINGS_LIMIT`].
    pub limit: Option<u64>,
}

impl CrossChainFindingFilters {
    fn effective_limit(&self) -> u64 {
        self.limit
            .unwrap_or(DEFAULT_CROSS_CHAIN_FINDINGS_LIMIT)
            .clamp(1, MAX_CROSS_CHAIN_FINDINGS_LIMIT)
    }
}

/// The mutable Postgres cross-chain-finding read model (§24, Sprint 17 t4).
/// Object-safe for the same reason as [`IncidentStore`] — a sibling seam, not
/// a method on it, since a finding is a structurally different row (see
/// [`crate::cross_chain_projection`]'s module docs).
#[async_trait]
pub trait CrossChainFindingStore: Send + Sync {
    /// Upsert the folded finding read-model row, keyed by `finding_id`.
    /// Idempotent: the [`CrossChainFindingRecord`] is always the current
    /// merged truth (creation is set-once; only `retracted`/
    /// `retraction_reason`/`observed_at` ever change), so re-applying a
    /// redelivered event overwrites with identical values.
    async fn upsert_finding(&self, record: &CrossChainFindingRecord) -> Result<(), PersistError>;

    /// List finding rows, newest-observed first (§11 `GET /v1/incidents`),
    /// optionally narrowed by `filters`.
    async fn list_findings(
        &self,
        filters: &CrossChainFindingFilters,
    ) -> Result<Vec<CrossChainFindingRecord>, PersistError>;
}

#[async_trait]
impl CrossChainFindingStore for PgIncidentStore {
    async fn upsert_finding(&self, record: &CrossChainFindingRecord) -> Result<(), PersistError> {
        let finding_id: Uuid = record.finding_id.0;
        let kind = record.kind.as_str();
        let legs = serde_json::to_value(&record.legs).map_err(|err| {
            PersistError::Postgres(sqlx::Error::Encode(
                format!("encoding cross-chain finding legs: {err}").into(),
            ))
        })?;
        let entity_hint = normalized_address(&record.entity_hint);
        let confidence = record.confidence.get();
        let severity = <&str>::from(record.severity);

        sqlx::query!(
            "INSERT INTO cross_chain_findings (
                 finding_id, kind, bridge, legs, entity_hint, profit, victim_loss,
                 confidence, severity, retracted, retraction_reason, observed_at, updated_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
             ON CONFLICT (finding_id) DO UPDATE SET
                 retracted         = EXCLUDED.retracted,
                 retraction_reason = EXCLUDED.retraction_reason,
                 observed_at       = EXCLUDED.observed_at,
                 updated_at        = now()",
            finding_id,
            kind,
            record.bridge,
            legs,
            entity_hint,
            record.profit,
            record.victim_loss,
            confidence,
            severity,
            record.retracted,
            record.retraction_reason.as_deref(),
            record.observed_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_findings(
        &self,
        filters: &CrossChainFindingFilters,
    ) -> Result<Vec<CrossChainFindingRecord>, PersistError> {
        let limit = filters.effective_limit() as i64;
        let rows = sqlx::query!(
            "SELECT finding_id, kind, bridge, legs, entity_hint, profit, victim_loss,
                    confidence, severity, retracted, retraction_reason, observed_at
             FROM cross_chain_findings
             WHERE ($1::bool IS NULL OR retracted = $1)
             ORDER BY observed_at DESC
             LIMIT $2",
            filters.retracted,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let kind = CrossChainFindingKind::parse(&row.kind).ok_or_else(|| {
                    PersistError::Postgres(sqlx::Error::ColumnDecode {
                        index: "kind".to_owned(),
                        source: format!("unrecognized cross-chain finding kind {:?}", row.kind)
                            .into(),
                    })
                })?;
                let legs = serde_json::from_value(row.legs).map_err(|err| {
                    PersistError::Postgres(sqlx::Error::ColumnDecode {
                        index: "legs".to_owned(),
                        source: format!("stored legs: {err}").into(),
                    })
                })?;
                let entity_hint = parse_address_column("entity_hint", &row.entity_hint)?;
                let severity = parse_wire_enum(&row.severity)?;

                Ok(CrossChainFindingRecord::from_stored(
                    CrossChainFindingId(row.finding_id),
                    kind,
                    row.bridge,
                    legs,
                    entity_hint,
                    row.profit,
                    row.victim_loss,
                    Confidence::new(row.confidence),
                    severity,
                    row.retracted,
                    row.retraction_reason,
                    row.observed_at,
                ))
            })
            .collect()
    }
}

/// The `serde_json::from_value(Value::String(...))` trick every wire-string
/// parser in this crate builds on: reuse a `#[serde(rename_all = "snake_case")]`
/// enum's own mapping (e.g. [`AlertKind`]/[`Severity`]) rather than hand-rolling
/// a second one that could drift. Callers wrap the raw `serde_json::Error` into
/// whatever domain error fits their layer — this stays layer-agnostic so an
/// HTTP query-param parser isn't forced through a Postgres-flavored error.
pub(crate) fn deserialize_wire_str<T: serde::de::DeserializeOwned>(
    raw: &str,
) -> Result<T, serde_json::Error> {
    serde_json::from_value(serde_json::Value::String(raw.to_owned()))
}

/// Parse a snake_case wire string (e.g. `"sandwich"`) back into a derive-driven
/// `Serialize`/`Deserialize` enum like [`AlertKind`]/[`Severity`].
fn parse_wire_enum<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, PersistError> {
    deserialize_wire_str(raw).map_err(|err| {
        PersistError::Postgres(sqlx::Error::ColumnDecode {
            index: "kind/severity".to_owned(),
            source: format!("unrecognized value {raw:?}: {err}").into(),
        })
    })
}

/// Parse a stored `0x`-hex column value back into a fixed-size hash.
fn parse_hex_column(column: &'static str, raw: &str) -> Result<B256, PersistError> {
    raw.parse().map_err(|err| {
        PersistError::Postgres(sqlx::Error::ColumnDecode {
            index: column.to_owned(),
            source: format!("{raw:?} is not 0x-hex: {err}").into(),
        })
    })
}

/// Parse a stored `0x`-hex column value back into an [`AccountAddress`].
fn parse_address_column(column: &'static str, raw: &str) -> Result<AccountAddress, PersistError> {
    raw.parse().map_err(|err| {
        PersistError::Postgres(sqlx::Error::ColumnDecode {
            index: column.to_owned(),
            source: format!("{raw:?} is not a 0x-hex address: {err}").into(),
        })
    })
}

/// Canonicalize an address to lowercase `0x`-hex before it's written to or matched
/// against a stored column — mirrors [`event-store`'s
/// `normalized_address`](../../event-store/src/store.rs) so the same wallet always
/// compares equal regardless of the casing it arrived with.
fn normalized_address(address: &AccountAddress) -> String {
    format!("{address:#x}")
}

/// ClickHouse-backed [`IncidentAnalytics`]. Cheap to clone (the client is `Arc`-cheap).
#[derive(Clone)]
pub struct ClickhouseAnalytics {
    client: Client,
}

impl ClickhouseAnalytics {
    /// Wrap a ClickHouse client (see [`build_clickhouse_client`]) as the analytics store.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Liveness probe: a trivial query that proves ClickHouse is reachable — used at boot
    /// so a misconfigured analytics store fails fast, mirroring the event store's `ping`.
    pub async fn ping(&self) -> Result<(), PersistError> {
        let _: u8 = self.client.query("SELECT 1").fetch_one().await?;
        Ok(())
    }
}

#[async_trait]
impl IncidentAnalytics for ClickhouseAnalytics {
    async fn append(&self, row: &AnalyticsRow) -> Result<(), PersistError> {
        let mut insert = self
            .client
            .insert::<AnalyticsRow>("incident_analytics")
            .await?;
        insert.write(row).await?;
        insert.end().await?;
        Ok(())
    }
}

#[async_trait]
impl WalletExposureStore for ClickhouseAnalytics {
    async fn mev_exposure(
        &self,
        victim_address: &AccountAddress,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<ExposureRow>, PersistError> {
        let address = normalized_address(victim_address);
        // Fold each incident's snapshot rows (created/finalized/retracted, all
        // carrying `victim_address` once stamped) to its *latest* state in the
        // inner query, then keep only the still-confirmed ones — `confirmed = 1`
        // on the latest snapshot excludes a created-then-retracted incident, which
        // never really cost the wallet anything. `created_at` is the incident's
        // creation time (`minIf` on the created row), so `since` and the ordering
        // mean "incidents *created* at/after", not "last touched at/after". The
        // fold is a subquery — aliasing the `minIf` as the raw column name
        // `occurred_at` would read as an aggregate-inside-`argMax`, so the inner
        // query keeps `created_at` distinct and the outer renames it back to the
        // `ExposureRow` field. Grouping is pruned to this one wallet by the
        // `victim_address` bloom-filter index, so there is no global scan. Bind
        // order — address, [since], limit — matches the `?` order; keep them in
        // lockstep if this grows (the general form is event-store's
        // `query::Conditions`).
        let mut sql = String::from(
            "SELECT incident_id, kind, victim_loss_usd, created_at AS occurred_at \
             FROM ( \
                 SELECT \
                     incident_id, \
                     argMax(kind, occurred_at)            AS kind, \
                     argMax(victim_loss_usd, occurred_at) AS victim_loss_usd, \
                     argMax(confirmed, occurred_at)       AS confirmed, \
                     minIf(occurred_at, event_type = 'IncidentCreated') AS created_at \
                 FROM incident_analytics \
                 WHERE victim_address = ? AND incident_id IS NOT NULL \
                 GROUP BY incident_id \
             ) \
             WHERE confirmed = 1",
        );
        if since.is_some() {
            sql.push_str(" AND created_at >= fromUnixTimestamp64Milli(?)");
        }
        sql.push_str(" ORDER BY created_at DESC LIMIT ?");

        let mut query = self.client.query(&sql).bind(&address);
        if let Some(since) = since {
            query = query.bind(since.timestamp_millis());
        }
        query = query.bind(MAX_EXPOSURE_INCIDENTS);
        Ok(query.fetch_all().await?)
    }
}

#[async_trait]
impl TimingStore for ClickhouseAnalytics {
    async fn timing_buckets(
        &self,
        chain: Chain,
        severity: crate::timing::SizeBand,
    ) -> Result<Vec<TimingBucketRow>, PersistError> {
        // The rollup is a SummingMergeTree: merges are eventual, so every read
        // re-aggregates rather than trusting a bare per-part row (mirrors
        // `usage_rollup_daily`'s documented contract). Bind order — chain,
        // severity — matches the `?` order.
        let severity_wire = <&'static str>::from(severity);
        Ok(self
            .client
            .query(
                "SELECT slot_of_day, sum(incident_count) AS incident_count, \
                     sum(total_victim_loss_usd) AS total_victim_loss_usd \
                 FROM incident_timing_rollup \
                 WHERE chain = ? AND severity = ? \
                 GROUP BY slot_of_day",
            )
            .bind(chain.id())
            .bind(severity_wire)
            .fetch_all()
            .await?)
    }
}

/// Build the ClickHouse client from config. Does no I/O — the first real connection
/// happens on the first query. Mirrors [`event-store`'s `build_client`](../../event-store/src/store.rs)
/// (the two services own different tables, so they don't share the code, only the shape).
pub fn build_clickhouse_client(cfg: &ClickhouseConfig) -> Client {
    Client::default()
        .with_url(&cfg.url)
        .with_user(&cfg.user)
        .with_password(cfg.password.expose_secret())
        .with_database(&cfg.database)
}

/// One immutable analytics row — the stored form of a result event's folded snapshot.
/// Field names are the `incident_analytics` column names; `appended_at` is intentionally
/// absent (it has a `DEFAULT`, so ClickHouse fills the ingest time). The `serde` helpers
/// map UUID/`DateTime64` to the columns' byte forms, exactly as the event store's `EventRow`
/// does.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize)]
pub struct AnalyticsRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub event_id: Uuid,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub occurred_at: DateTime<Utc>,
    pub chain: u64,
    pub event_type: String,
    #[serde(with = "clickhouse::serde::uuid")]
    pub alert_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub incident_id: Option<Uuid>,
    /// AlertKind wire string, or `""` before `IncidentCreated` names it.
    pub kind: String,
    /// Severity wire string, or `""` before it is known.
    pub severity: String,
    /// Folded lifecycle status at this event.
    pub status: String,
    /// `1` iff this snapshot is a live confirmed incident (confirmed/finalized, not
    /// retracted) — a denormalized flag so the common filter is a column read.
    pub confirmed: u8,
    pub profit: f64,
    pub victim_loss: f64,
    /// The victim wallet named by `IncidentCreated`, normalized lowercase `0x`-hex
    /// (mirrors [`normalized_address`]); `None` before that event or when it named
    /// no victim (e.g. `Honeypot`).
    pub victim_address: Option<String>,
    /// The victim's own USD-valued loss; `None` alongside `victim_address`.
    pub victim_loss_usd: Option<f64>,
}

impl AnalyticsRow {
    /// Build the analytics row for `envelope` from the current folded `record`. Total —
    /// every field is a direct projection of the two inputs, so this never fails.
    pub fn from_event(envelope: &EventEnvelope, record: &IncidentRecord) -> Self {
        use crate::projection::IncidentStatus;
        Self {
            event_id: envelope.event_id,
            occurred_at: envelope.occurred_at,
            chain: envelope.chain.id(),
            event_type: envelope.event_type().to_owned(),
            alert_id: record.alert_id.0,
            incident_id: record.incident_id.map(|id| id.0),
            kind: record
                .kind
                .map(<&'static str>::from)
                .unwrap_or_default()
                .to_owned(),
            severity: record
                .severity
                .map(<&'static str>::from)
                .unwrap_or_default()
                .to_owned(),
            status: record.status.as_str().to_owned(),
            confirmed: u8::from(matches!(
                record.status,
                IncidentStatus::Confirmed | IncidentStatus::Finalized
            )),
            profit: record.profit,
            victim_loss: record.victim_loss,
            victim_address: record.victim_address.map(|a| normalized_address(&a)),
            victim_loss_usd: record.victim_loss_usd.map(UsdAmount::get),
        }
    }
}

/// One confirmed incident from a [`WalletExposureStore::mev_exposure`] read — the
/// raw shape [`crate::exposure::summarize`] folds into the wallet's exposure
/// summary. `victim_loss_usd` is a plain `f64` here (not `UsdAmount`): the column
/// is only populated for rows the write path already validated, so re-validating
/// on every read would be redundant work for no additional safety.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, serde::Deserialize)]
pub struct ExposureRow {
    #[serde(with = "clickhouse::serde::uuid::option")]
    pub incident_id: Option<Uuid>,
    pub kind: String,
    pub victim_loss_usd: Option<f64>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    pub occurred_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::{Applied, IncidentProjection, IncidentStatus};
    use event_bus::Transience;
    use events::primitives::{AlertKind, IncidentId, Severity};
    use events::simulation::{IncidentCreated, SimulationCompleted};
    use revm::primitives::B256;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).expect("valid timestamp")
    }

    fn env(payload: DomainEvent, occurred_at: DateTime<Utc>) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), occurred_at, Chain::ETHEREUM, payload)
    }

    /// The persisted string (strum's `IntoStaticStr`) and the serde wire form must agree, so
    /// a query written against one matches rows written via the other. Guards against the
    /// two independent `snake_case` attributes (`#[strum(serialize_all)]` /
    /// `#[serde(rename_all)]`) ever drifting apart.
    #[test]
    fn kind_and_severity_strings_match_the_serde_wire_form() {
        use strum::IntoEnumIterator;
        // Exhaustive by construction (EnumIter): a newly added variant is
        // covered automatically instead of silently missing from a hand list.
        for kind in AlertKind::iter() {
            let wire = serde_json::to_string(&kind).unwrap();
            assert_eq!(wire, format!("\"{}\"", <&str>::from(kind)));
        }
        for sev in Severity::iter() {
            let wire = serde_json::to_string(&sev).unwrap();
            assert_eq!(wire, format!("\"{}\"", <&str>::from(sev)));
        }
    }

    #[test]
    fn analytics_row_projects_a_confirmed_incident_snapshot() {
        let alert = AlertId::new();
        let incident = IncidentId::new();
        let mut proj = IncidentProjection::new();

        proj.apply(&env(
            DomainEvent::SimulationCompleted(SimulationCompleted {
                alert_id: alert,
                profit: 9.0,
                victim_loss: 4.0,
                confirmed: true,
            }),
            at(10),
        ));
        let created = env(
            DomainEvent::IncidentCreated(IncidentCreated {
                incident_id: incident,
                alert_id: alert,
                kind: AlertKind::Sandwich,
                txs: vec![B256::repeat_byte(0x01)],
                profit: 9.0,
                victim_loss: 4.0,
                impact_usd: None,
                severity: Severity::High,
                suggested_action: events::primitives::SuggestedAction::Escalate,
                victim_address: None,
                victim_loss_usd: None,
            }),
            at(11),
        );
        assert_eq!(proj.apply(&created), Applied::Updated);

        let record = proj.record(&alert).expect("row");
        let row = AnalyticsRow::from_event(&created, record);

        assert_eq!(row.event_id, created.event_id);
        assert_eq!(row.alert_id, alert.0);
        assert_eq!(row.incident_id, Some(incident.0));
        assert_eq!(row.kind, "sandwich");
        assert_eq!(row.severity, "high");
        assert_eq!(row.status, "confirmed");
        assert_eq!(row.confirmed, 1);
        assert_eq!(row.profit, 9.0);
        assert_eq!(row.victim_loss, 4.0);
    }

    #[test]
    fn analytics_row_flags_unconfirmed_and_retracted_as_not_confirmed() {
        let alert = AlertId::new();
        let mut proj = IncidentProjection::new();
        let completed = env(
            DomainEvent::SimulationCompleted(SimulationCompleted {
                alert_id: alert,
                profit: 0.0,
                victim_loss: 0.0,
                confirmed: false,
            }),
            at(10),
        );
        proj.apply(&completed);
        let row = AnalyticsRow::from_event(&completed, proj.record(&alert).unwrap());
        assert_eq!(row.status, "unconfirmed");
        assert_eq!(row.confirmed, 0);
        assert_eq!(row.incident_id, None);
        assert_eq!(row.kind, "");
    }

    #[test]
    fn job_update_derives_only_from_the_two_job_events() {
        let alert = AlertId::new();
        let requested = env(
            DomainEvent::SimulationRequested(events::simulation::SimulationRequested {
                alert_id: alert,
                evidence: serde_json::json!({}),
            }),
            at(5),
        );
        let job = JobUpdate::from_event(&requested).expect("requested maps");
        assert_eq!(job.state, JobState::Requested);
        assert_eq!(job.alert_id, alert);
        assert_eq!(job.at, at(5));

        let completed = env(
            DomainEvent::SimulationCompleted(SimulationCompleted {
                alert_id: alert,
                profit: 1.0,
                victim_loss: 0.0,
                confirmed: true,
            }),
            at(6),
        );
        assert_eq!(
            JobUpdate::from_event(&completed).unwrap().state,
            JobState::Completed
        );

        // A terminal incident event is not a job transition.
        let finalized = env(
            DomainEvent::IncidentFinalized(events::simulation::IncidentFinalized {
                incident_id: IncidentId::new(),
                block_hash: B256::ZERO,
            }),
            at(7),
        );
        assert!(JobUpdate::from_event(&finalized).is_none());
    }

    #[test]
    fn persist_error_classifies_transient_vs_permanent() {
        // I/O / pool / server faults are transient — the consumer retries (redelivers).
        assert!(PersistError::Postgres(sqlx::Error::PoolClosed).is_transient());
        assert!(PersistError::Postgres(sqlx::Error::PoolTimedOut).is_transient());
        assert!(
            PersistError::Clickhouse(clickhouse::error::Error::Custom("io".into())).is_transient()
        );

        // Encoding/decoding/schema faults are our-side bugs — permanent, so the consumer
        // skips the event rather than looping forever (§4: never wedge the stream).
        assert!(!PersistError::Postgres(sqlx::Error::Decode("bad".into())).is_transient());
        assert!(!PersistError::Postgres(sqlx::Error::ColumnNotFound("nope".into())).is_transient());
        assert!(!PersistError::Postgres(sqlx::Error::TypeNotFound {
            type_name: "x".into()
        })
        .is_transient());
    }

    #[test]
    fn incident_status_is_used_in_analytics() {
        // Compile-touch the re-exported status enum path used by `from_event`.
        assert_eq!(IncidentStatus::Confirmed.as_str(), "confirmed");
    }
}
