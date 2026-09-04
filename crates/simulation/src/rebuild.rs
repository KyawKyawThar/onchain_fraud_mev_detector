//! The simulation service's read models, made rebuildable (readiness Epic B).
//!
//! The [`rebuild`] implementation for everything the `simulation-projection`
//! consumer derives — the incident read model ("incidents"), the cross-chain
//! findings beside it, and the ClickHouse analytics firehose the §19 dashboards
//! read ("dashboards"). Rebuild it from the event store, prove it is
//! byte-identical, swap it in.
//!
//! ## Staging is a namespace, not a schema change
//!
//! A rebuild never truncates a live table. It builds the replacement in a
//! **staging namespace** beside the live one and swaps:
//!
//! * **Postgres** — a schema (`rebuild_simulation_…`) holding
//!   `CREATE TABLE … (LIKE public.<t> INCLUDING ALL)` copies. The projector's
//!   pool has that schema first on its `search_path` ([`db::connect_in_schema`]),
//!   so [`PgIncidentStore`] writes there **unmodified**: same type, same SQL,
//!   same upserts. `LIKE … INCLUDING ALL` rather than re-running migrations,
//!   because it copies whatever is *actually live* and so cannot drift from it.
//! * **ClickHouse** — a database, populated by running this crate's own
//!   [`ch_migrate::MIGRATOR`] against it, so the staged tables and the
//!   materialized view are created from the production DDL. The analytics
//!   client is simply `with_database(staging)`.
//!
//! This is the whole reason the fold can go through the live path: nothing about
//! the write path knows it is being rebuilt. Point the connection somewhere else
//! and the same code writes somewhere else.
//!
//! ## It folds through the live consumer, not a copy of it
//!
//! [`SimulationProjector::apply`] calls
//! [`ProjectionConsumer::handle`](crate::projection_consumer::ProjectionConsumer)
//! — the exact `EventHandler` Kafka drives in production, with the broker taken
//! out of the loop. There is no second fold to keep in sync, so a rebuild cannot
//! drift from the live path, and a bug in the fold shows up in both places
//! rather than cancelling itself out. A rebuild that re-implements the
//! projection proves that the re-implementation agrees with itself, which is
//! worth nothing.
//!
//! ## Promotion, and exactly how atomic it is
//!
//! * **Postgres is atomic.** DDL is transactional there, so one transaction
//!   moves the live tables out to a `…_superseded` schema and the staged ones
//!   in. A reader never sees half the tables swapped. The superseded schema is
//!   **kept**, not dropped: it is the only copy of any `lost` row, and it is the
//!   rollback if a promotion turns out to have been a mistake. Dropping it is an
//!   operator's explicit step (runbook §6).
//! * **ClickHouse is not.** `EXCHANGE TABLES` is pairwise, and the analytics
//!   firehose and its rollup are two tables, so there is a sub-millisecond
//!   window where a dashboard query could read one swapped and one not. Stated
//!   rather than papered over — and tolerable precisely because these are the
//!   trend surface, not the system of record (the event store is). The Postgres
//!   read model, which the §11 API serves to customers, has no such window.
//!
//! ## Targets
//!
//! | target | tables | claim |
//! |---|---|---|
//! | [`Targets::Postgres`] | `incidents`, `sim_jobs`, `cross_chain_findings` | **byte-identical**, atomically promoted |
//! | [`Targets::Clickhouse`] | `incident_analytics`, `incident_timing_rollup` | rebuildable; see the caveat below |
//! | [`Targets::All`] | both | one replay drives both |
//!
//! ### The ClickHouse caveat, stated up front
//!
//! `incident_analytics` is appended only when the fold reports a *real* change,
//! and `projection_consumer`'s docs already record the gap: a store fault
//! landing between a successful `incidents` upsert and the analytics append,
//! followed by a Kafka redelivery that re-folds to `Duplicate`, drops that
//! analytics row for good. A rebuild sees every event exactly once and therefore
//! *does* produce it. So a `gained`-class divergence here is the expected shape
//! of that known debt — the rebuild is the first thing that can measure it —
//! while `lost` or `changed` is a real finding.
//!
//! `incident_timing_rollup` is a `SummingMergeTree` fed by a materialized view
//! on inserts into `incident_analytics`; staging gets its own copy of both, so
//! the rollup is rebuilt by the same trigger that maintains it live. It is
//! fingerprinted through an aggregating read (`sum(…) GROUP BY …`), never a raw
//! scan: merges are eventual, so the physical row count is not a stable value
//! and a raw scan would report unmerged parts as a divergence.
//!
//! ## Full scope only
//!
//! [`ScopeSupport::FullOnly`], declared once and enforced by the driver. A
//! staged rebuild promotes a *complete* replacement, so a narrowed scope would
//! promote a table missing everything outside the window — and an `incidents`
//! row is folded from events that can straddle any window, so the narrowing is
//! not even expressible.
//!
//! ## Excluded columns
//!
//! `incidents.updated_at`, `sim_jobs.updated_at`,
//! `cross_chain_findings.updated_at` and `incident_analytics.appended_at` are
//! excluded from every fingerprint. Each is `now()` at write time — a clock, not
//! a projection. **Every other column is compared**, including the event-time
//! watermarks (`figures_at`, `retracted_at`, `finalized_at`, `observed_at`),
//! which are derived from event payloads and must reproduce exactly.
//!
//! ## Why the SQL here is runtime-checked, not `query!`
//!
//! These are whole-table scans and DDL with no compile-time-interesting types,
//! and they run against tables whose *schema* is fixed but whose *namespace* is
//! chosen at runtime — which a compile-time-verified query cannot express.
//! Keeping them out of the `.sqlx` cache also means the recovery procedure does
//! not acquire a build-time dependency on a prepared query cache.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clickhouse::Client;
use event_bus::{EventHandler, Handled};
use events::EventEnvelope;
use rebuild::digest::{ModelDigest, RowEncoder};
use rebuild::model::{ModelError, Projector, Scope, ScopeSupport, Snapshotter, Stageable, Staging};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

use crate::ch_migrate;
use crate::projection_consumer::{consumed_event_types, ProjectionConsumer};
use crate::store::{
    AnalyticsRow, ClickhouseAnalytics, CrossChainFindingStore, IncidentAnalytics, IncidentPage,
    IncidentStore, JobUpdate, PersistError, PgIncidentStore,
};

/// Rows per page when scanning a table to fingerprint it. Bounds the
/// per-round-trip allocation; the digest itself is one key plus 32 bytes per
/// row, which is the memory the exercise is actually about.
const SCAN_PAGE: i64 = 5_000;

/// The Postgres tables this read model owns, in the order they are created and
/// swapped. One list, used by staging, promotion and cleanup, so the three can
/// never cover different tables.
const PG_TABLES: [&str; 3] = ["incidents", "sim_jobs", "cross_chain_findings"];

/// The ClickHouse tables that hold data (the materialized view is a trigger,
/// not a table, and stays attached to whatever `incident_analytics` names).
const CH_TABLES: [&str; 2] = ["incident_analytics", "incident_timing_rollup"];

/// Which of the simulation service's stores a rebuild acts on — the operator's
/// `--model` choice, before any connection has been made.
///
/// This is the *name* of a target; [`Stores`] is the target plus the
/// connections it needs. Separate types because a CLI parses a name long before
/// a pool exists, and only [`Stores`] may reach [`SimulationReadModel::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Targets {
    /// The mutable Postgres read model only.
    Postgres,
    /// The ClickHouse analytics firehose (and its rollup) only.
    Clickhouse,
    /// Both, from one replay.
    All,
}

impl Targets {
    /// Parse the CLI/operator spelling.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "postgres" | "incidents" => Some(Targets::Postgres),
            "clickhouse" | "analytics" | "dashboards" => Some(Targets::Clickhouse),
            "all" => Some(Targets::All),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Targets::Postgres => "simulation-incidents",
            Targets::Clickhouse => "simulation-analytics",
            Targets::All => "simulation-projection",
        }
    }
}

/// A live Postgres connection **and the URL to open more like it**.
///
/// The URL is not redundant: staging needs a *second* pool whose `search_path`
/// points at the staging schema, and a pool cannot be re-pointed after it is
/// built. Held as a [`SecretString`] because it embeds the password.
#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
    url: SecretString,
}

impl PostgresStore {
    pub fn new(pool: PgPool, url: SecretString) -> Self {
        Self { pool, url }
    }
}

/// A target **together with the connections that target requires** — the
/// argument [`SimulationReadModel::new`] takes.
///
/// Why this rather than `(Targets, Option<PgPool>, Option<Client>)`: that shape
/// makes four illegal states representable (a Postgres target with no pool, and
/// so on), catchable only by a runtime assertion — a panic at boot for a wiring
/// mistake the compiler can see. Conventions §4: illegal states are
/// unrepresentable, not re-validated at the boundary.
// No `Debug`: `clickhouse::Client` does not implement it, and these variants
// hold live connections whose config embeds credentials — a `{:?}` of one has
// no business in a log line.
#[derive(Clone)]
pub enum Stores {
    /// Rebuild the Postgres read model; the analytics firehose is left alone.
    Postgres(PostgresStore),
    /// Rebuild the ClickHouse analytics firehose; Postgres is left alone.
    Clickhouse(Client),
    /// Rebuild both from one replay.
    Both {
        postgres: PostgresStore,
        clickhouse: Client,
    },
}

impl Stores {
    /// Which target this is — derived, never passed alongside, so the name and
    /// the connections cannot disagree.
    pub fn targets(&self) -> Targets {
        match self {
            Stores::Postgres(_) => Targets::Postgres,
            Stores::Clickhouse(_) => Targets::Clickhouse,
            Stores::Both { .. } => Targets::All,
        }
    }

    fn postgres(&self) -> Option<&PostgresStore> {
        match self {
            Stores::Postgres(pg) | Stores::Both { postgres: pg, .. } => Some(pg),
            Stores::Clickhouse(_) => None,
        }
    }

    fn clickhouse(&self) -> Option<&Client> {
        match self {
            Stores::Clickhouse(client)
            | Stores::Both {
                clickhouse: client, ..
            } => Some(client),
            Stores::Postgres(_) => None,
        }
    }
}

/// An [`IncidentStore`]/[`IncidentAnalytics`]/[`CrossChainFindingStore`] that
/// swallows every write.
///
/// Not a test double: it is how `--model dashboards` avoids writing the Postgres
/// rows it is not rebuilding while still driving the real [`ProjectionConsumer`],
/// so the ClickHouse rows come out of the real fold.
#[derive(Debug, Default)]
struct NoWrites;

#[async_trait]
impl IncidentStore for NoWrites {
    async fn upsert_incident(
        &self,
        _record: &crate::projection::IncidentRecord,
    ) -> Result<(), PersistError> {
        Ok(())
    }

    async fn record_job(&self, _job: &JobUpdate) -> Result<(), PersistError> {
        Ok(())
    }

    async fn list_incidents(
        &self,
        _filters: &crate::store::IncidentFilters,
    ) -> Result<IncidentPage, PersistError> {
        Ok(IncidentPage {
            incidents: Vec::new(),
            next_cursor: None,
        })
    }
}

#[async_trait]
impl IncidentAnalytics for NoWrites {
    async fn append(&self, _row: &AnalyticsRow) -> Result<(), PersistError> {
        Ok(())
    }
}

#[async_trait]
impl CrossChainFindingStore for NoWrites {
    async fn upsert_finding(
        &self,
        _record: &crate::cross_chain_projection::CrossChainFindingRecord,
    ) -> Result<(), PersistError> {
        Ok(())
    }

    async fn list_findings(
        &self,
        _filters: &crate::store::CrossChainFindingFilters,
    ) -> Result<Vec<crate::cross_chain_projection::CrossChainFindingRecord>, PersistError> {
        Ok(Vec::new())
    }
}

/// The fold half, bound to one staging area.
///
/// Holds a real [`ProjectionConsumer`] whose stores point at the staging
/// namespace, plus the staging pool itself so it lives as long as the projector
/// (dropping it would close the connections the consumer is writing through).
pub struct SimulationProjector {
    consumer: ProjectionConsumer,
    /// Kept alive for the consumer's sake; never used directly.
    _staging_pool: Option<PgPool>,
}

#[async_trait]
impl Projector for SimulationProjector {
    fn event_types(&self) -> Vec<String> {
        // Exactly the list the live consumer subscribes to — one source of
        // truth, so a newly consumed event type is replayed automatically
        // instead of being silently absent from every future rebuild.
        consumed_event_types()
    }

    async fn apply(&self, envelope: EventEnvelope) -> Result<(), ModelError> {
        // Kept for the error messages below, which name the event that stopped
        // the run — the handler consumes the envelope itself.
        let (event_id, event_type) = (envelope.event_id, envelope.event_type());
        // The live handler, verbatim. Its verdicts mean something different
        // here: there is no broker to redeliver and no DLQ to park in, so every
        // non-`Commit` outcome is a stop, not a routing decision.
        match self.consumer.handle(envelope).await {
            Handled::Commit => Ok(()),
            Handled::Retry => Err(ModelError::new(format!(
                "transient store fault folding event {event_id} ({event_type}); a rebuild has no \
                 redelivery, so this stops the run"
            ))),
            Handled::Skip { reason } => Err(ModelError::new(format!(
                "event {event_id} ({event_type}) was rejected as poison during a rebuild: \
                 {reason}. Live, this would be dead-lettered and the projection would carry on \
                 missing it — during a rebuild it is a hard stop, because the result would be a \
                 plausible wrong projection rather than a visible gap"
            ))),
            Handled::Stop => Err(ModelError::new("the handler asked the consumer to stop")),
        }
    }

    async fn flush(&self) -> Result<(), ModelError> {
        // Write-through: nothing is buffered. Terminal events still orphaned in
        // the fold (an `IncidentRetracted` whose `IncidentCreated` never
        // appeared) legitimately have no row to write — the same state the live
        // consumer would be in.
        Ok(())
    }
}

/// The simulation service's rebuildable read models.
pub struct SimulationReadModel {
    targets: Targets,
    postgres: Option<PostgresStore>,
    clickhouse: Option<Client>,
}

impl SimulationReadModel {
    /// Build over `stores`. Total — every [`Stores`] variant carries exactly the
    /// connections its target needs, so there is nothing to validate.
    pub fn new(stores: Stores) -> Self {
        Self {
            targets: stores.targets(),
            postgres: stores.postgres().cloned(),
            clickhouse: stores.clickhouse().cloned(),
        }
    }

    /// The ClickHouse client scoped to a staging database.
    fn staged_clickhouse(&self, staging: &Staging) -> Option<Client> {
        self.clickhouse
            .as_ref()
            .map(|client| client.clone().with_database(staging.id()))
    }

    /// Fingerprint every table this model owns, through whichever connections
    /// are handed in. The *same* function serves the live and the staged
    /// fingerprint — only the namespace the connections point at differs, which
    /// is what makes the two comparable at all.
    async fn digest_through(
        pool: Option<&PgPool>,
        clickhouse: Option<&Client>,
    ) -> Result<ModelDigest, ModelError> {
        let mut digest = ModelDigest::new();
        if let Some(pool) = pool {
            Self::digest_incidents(pool, &mut digest).await?;
            Self::digest_jobs(pool, &mut digest).await?;
            Self::digest_findings(pool, &mut digest).await?;
        }
        if let Some(client) = clickhouse {
            Self::digest_analytics(client, &mut digest).await?;
            Self::digest_timing_rollup(client, &mut digest).await?;
        }
        Ok(digest)
    }

    /// Fingerprint `incidents` — one page at a time, keyed by `alert_id` (the
    /// primary key, and the key the fold itself uses).
    async fn digest_incidents(pool: &PgPool, digest: &mut ModelDigest) -> Result<(), ModelError> {
        let mut after: Option<Uuid> = None;
        loop {
            let rows = sqlx::query(
                "SELECT alert_id, incident_id, status, kind, severity, profit, victim_loss,
                        txs, victim_address, victim_loss_usd, retraction_reason, finalized_block,
                        figures_at, retracted_at, finalized_at
                 FROM incidents
                 WHERE $1::uuid IS NULL OR alert_id > $1
                 ORDER BY alert_id
                 LIMIT $2",
            )
            .bind(after)
            .bind(SCAN_PAGE)
            .fetch_all(pool)
            .await
            .map_err(|err| ModelError::wrap("scanning incidents", err))?;

            if rows.is_empty() {
                return Ok(());
            }
            for row in &rows {
                let alert_id: Uuid = get(row, "alert_id")?;
                let encoded = RowEncoder::new()
                    .text(&alert_id.to_string())
                    .optional_text(
                        get::<Option<Uuid>>(row, "incident_id")?
                            .map(|id| id.to_string())
                            .as_deref(),
                    )
                    .text(&get::<String>(row, "status")?)
                    .optional_text(get::<Option<String>>(row, "kind")?.as_deref())
                    .optional_text(get::<Option<String>>(row, "severity")?.as_deref())
                    .float(get(row, "profit")?)
                    .float(get(row, "victim_loss")?)
                    .text_seq(get::<Vec<String>>(row, "txs")?.iter().map(String::as_str))
                    .optional_text(get::<Option<String>>(row, "victim_address")?.as_deref())
                    .optional_float(get(row, "victim_loss_usd")?)
                    .optional_text(get::<Option<String>>(row, "retraction_reason")?.as_deref())
                    .optional_text(get::<Option<String>>(row, "finalized_block")?.as_deref())
                    .timestamp(get(row, "figures_at")?)
                    .optional_timestamp(get(row, "retracted_at")?)
                    .optional_timestamp(get(row, "finalized_at")?)
                    .finish();
                insert(digest, format!("incidents/{alert_id}"), encoded)?;
                after = Some(alert_id);
            }
        }
    }

    /// Fingerprint `sim_jobs`.
    async fn digest_jobs(pool: &PgPool, digest: &mut ModelDigest) -> Result<(), ModelError> {
        let mut after: Option<Uuid> = None;
        loop {
            let rows = sqlx::query(
                "SELECT alert_id, chain, status, requested_at, completed_at
                 FROM sim_jobs
                 WHERE $1::uuid IS NULL OR alert_id > $1
                 ORDER BY alert_id
                 LIMIT $2",
            )
            .bind(after)
            .bind(SCAN_PAGE)
            .fetch_all(pool)
            .await
            .map_err(|err| ModelError::wrap("scanning sim_jobs", err))?;

            if rows.is_empty() {
                return Ok(());
            }
            for row in &rows {
                let alert_id: Uuid = get(row, "alert_id")?;
                let encoded = RowEncoder::new()
                    .text(&alert_id.to_string())
                    .int(get::<i64>(row, "chain")?)
                    .text(&get::<String>(row, "status")?)
                    .optional_timestamp(get(row, "requested_at")?)
                    .optional_timestamp(get(row, "completed_at")?)
                    .finish();
                insert(digest, format!("sim_jobs/{alert_id}"), encoded)?;
                after = Some(alert_id);
            }
        }
    }

    /// Fingerprint `cross_chain_findings`. `legs` is JSONB: Postgres normalises
    /// object key order on the way in, and `serde_json`'s default map is
    /// sorted, so re-serialising the value read back is canonical.
    async fn digest_findings(pool: &PgPool, digest: &mut ModelDigest) -> Result<(), ModelError> {
        let mut after: Option<Uuid> = None;
        loop {
            let rows = sqlx::query(
                "SELECT finding_id, kind, bridge, legs, entity_hint, profit, victim_loss,
                        confidence, severity, retracted, retraction_reason, observed_at
                 FROM cross_chain_findings
                 WHERE $1::uuid IS NULL OR finding_id > $1
                 ORDER BY finding_id
                 LIMIT $2",
            )
            .bind(after)
            .bind(SCAN_PAGE)
            .fetch_all(pool)
            .await
            .map_err(|err| ModelError::wrap("scanning cross_chain_findings", err))?;

            if rows.is_empty() {
                return Ok(());
            }
            for row in &rows {
                let finding_id: Uuid = get(row, "finding_id")?;
                let legs: serde_json::Value = get(row, "legs")?;
                let legs = serde_json::to_string(&legs)
                    .map_err(|err| ModelError::wrap("re-encoding cross-chain legs", err))?;
                let encoded = RowEncoder::new()
                    .text(&finding_id.to_string())
                    .text(&get::<String>(row, "kind")?)
                    .text(&get::<String>(row, "bridge")?)
                    .text(&legs)
                    .text(&get::<String>(row, "entity_hint")?)
                    .float(get(row, "profit")?)
                    .float(get(row, "victim_loss")?)
                    .float(get(row, "confidence")?)
                    .text(&get::<String>(row, "severity")?)
                    .int(i64::from(get::<bool>(row, "retracted")?))
                    .optional_text(get::<Option<String>>(row, "retraction_reason")?.as_deref())
                    .timestamp(get(row, "observed_at")?)
                    .finish();
                insert(
                    digest,
                    format!("cross_chain_findings/{finding_id}"),
                    encoded,
                )?;
                after = Some(finding_id);
            }
        }
    }

    /// Fingerprint `incident_analytics`, keyed by the triggering `event_id` —
    /// one row per event that changed something, which is the table's own
    /// identity.
    async fn digest_analytics(client: &Client, digest: &mut ModelDigest) -> Result<(), ModelError> {
        // No literal question marks anywhere in this SQL: the clickhouse client
        // parses every `?` as a bind placeholder, comments included.
        let mut cursor = client
            .query(
                "SELECT event_id, occurred_at, chain, event_type, alert_id, incident_id, \
                 kind, severity, status, confirmed, profit, victim_loss, \
                 victim_address, victim_loss_usd \
                 FROM incident_analytics ORDER BY event_id",
            )
            .fetch::<AnalyticsScanRow>()
            .map_err(|err| ModelError::wrap("scanning incident_analytics", err))?;

        while let Some(row) = cursor
            .next()
            .await
            .map_err(|err| ModelError::wrap("reading incident_analytics", err))?
        {
            let encoded = RowEncoder::new()
                .text(&row.event_id.to_string())
                .timestamp(row.occurred_at)
                .int(row.chain as i64)
                .text(&row.event_type)
                .text(&row.alert_id.to_string())
                .optional_text(row.incident_id.map(|id| id.to_string()).as_deref())
                .text(&row.kind)
                .text(&row.severity)
                .text(&row.status)
                .int(i64::from(row.confirmed))
                .float(row.profit)
                .float(row.victim_loss)
                .optional_text(row.victim_address.as_deref())
                .optional_float(row.victim_loss_usd)
                .finish();
            insert(
                digest,
                format!("incident_analytics/{}", row.event_id),
                encoded,
            )?;
        }
        Ok(())
    }

    /// Fingerprint `incident_timing_rollup` **through an aggregating read**.
    ///
    /// A `SummingMergeTree` holds one row per key per unmerged part, and merges
    /// are eventual — so the physical rows are not a stable value and a raw scan
    /// would report unmerged parts as a divergence. The aggregate is what the
    /// read path (`GET /v1/timing/recommendation`) actually sees, which is what
    /// a rebuild owes.
    async fn digest_timing_rollup(
        client: &Client,
        digest: &mut ModelDigest,
    ) -> Result<(), ModelError> {
        let mut cursor = client
            .query(
                "SELECT chain, severity, slot_of_day, \
                 sum(incident_count) AS incident_count, \
                 sum(total_victim_loss_usd) AS total_victim_loss_usd \
                 FROM incident_timing_rollup \
                 GROUP BY chain, severity, slot_of_day \
                 ORDER BY chain, severity, slot_of_day",
            )
            .fetch::<TimingScanRow>()
            .map_err(|err| ModelError::wrap("scanning incident_timing_rollup", err))?;

        while let Some(row) = cursor
            .next()
            .await
            .map_err(|err| ModelError::wrap("reading incident_timing_rollup", err))?
        {
            let encoded = RowEncoder::new()
                .int(row.chain as i64)
                .text(&row.severity)
                .int(i64::from(row.slot_of_day))
                .int(row.incident_count as i64)
                .float(row.total_victim_loss_usd)
                .finish();
            insert(
                digest,
                format!(
                    "incident_timing_rollup/{}/{}/{}",
                    row.chain, row.severity, row.slot_of_day
                ),
                encoded,
            )?;
        }
        Ok(())
    }
}

/// The ClickHouse scan row for `incident_analytics`. Separate from
/// [`AnalyticsRow`] (which is `Serialize`-only, for the insert) so the read side
/// names exactly the derived columns and never `appended_at`.
#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct AnalyticsScanRow {
    #[serde(with = "clickhouse::serde::uuid")]
    event_id: Uuid,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    occurred_at: DateTime<Utc>,
    chain: u64,
    event_type: String,
    #[serde(with = "clickhouse::serde::uuid")]
    alert_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid::option")]
    incident_id: Option<Uuid>,
    kind: String,
    severity: String,
    status: String,
    confirmed: u8,
    profit: f64,
    victim_loss: f64,
    victim_address: Option<String>,
    victim_loss_usd: Option<f64>,
}

/// The aggregated `incident_timing_rollup` read.
#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct TimingScanRow {
    chain: u64,
    severity: String,
    slot_of_day: u16,
    incident_count: u64,
    total_victim_loss_usd: f64,
}

#[async_trait]
impl Snapshotter for SimulationReadModel {
    fn name(&self) -> &'static str {
        self.targets.name()
    }

    fn scope_support(&self) -> ScopeSupport {
        // See the module docs: a staged rebuild promotes a complete
        // replacement, and an `incidents` row is folded from events that can
        // straddle any window.
        ScopeSupport::FullOnly
    }

    async fn digest(&self, _scope: &Scope) -> Result<ModelDigest, ModelError> {
        Self::digest_through(
            self.postgres.as_ref().map(|pg| &pg.pool),
            self.clickhouse.as_ref(),
        )
        .await
    }
}

#[async_trait]
impl Stageable for SimulationReadModel {
    async fn stage(&self, staging: &Staging) -> Result<Arc<dyn Projector>, ModelError> {
        // ── Postgres: a schema of `LIKE … INCLUDING ALL` copies ──────────
        // `INCLUDING ALL` carries defaults, constraints, indexes and identity
        // across, so the staged table is the live table's definition by
        // construction and cannot drift from it the way a re-run migration
        // could.
        let staging_pool = match &self.postgres {
            None => None,
            Some(pg) => {
                let mut ddl = format!("CREATE SCHEMA \"{}\";\n", staging.id());
                for table in PG_TABLES {
                    ddl.push_str(&format!(
                        "CREATE TABLE \"{}\".{table} (LIKE public.{table} INCLUDING ALL);\n",
                        staging.id()
                    ));
                }
                sqlx::raw_sql(sqlx::AssertSqlSafe(ddl))
                    .execute(&pg.pool)
                    .await
                    .map_err(|err| ModelError::wrap("creating the Postgres staging schema", err))?;

                // A second pool whose every connection resolves unqualified
                // names in the staging schema — this is what lets the
                // *unmodified* production write path target it.
                Some(
                    db::connect_in_schema(pg.url.expose_secret(), staging.id())
                        .await
                        .map_err(|err| {
                            ModelError::wrap(
                                "opening a staging-scoped Postgres pool",
                                // `anyhow::Error` is not `std::error::Error`;
                                // carry its rendering instead.
                                std::io::Error::other(err.to_string()),
                            )
                        })?,
                )
            }
        };

        // ── ClickHouse: a database, populated by this crate's own migrator ──
        // Running the production migration set is what gets the materialized
        // view as well as the two tables, from the same DDL production uses.
        let staged_ch = match self.staged_clickhouse(staging) {
            None => None,
            Some(client) => {
                self.clickhouse
                    .as_ref()
                    .expect("checked by staged_clickhouse")
                    .query(&format!("CREATE DATABASE \"{}\"", staging.id()))
                    .execute()
                    .await
                    .map_err(|err| {
                        ModelError::wrap("creating the ClickHouse staging database", err)
                    })?;
                ch_migrate::MIGRATOR.run(&client).await.map_err(|err| {
                    ModelError::wrap(
                        "creating the staged analytics schema",
                        std::io::Error::other(err.to_string()),
                    )
                })?;
                Some(client)
            }
        };

        // Wire the real consumer over the staged stores. A store this run does
        // not target gets `NoWrites` — never the live one, which is what makes
        // a `verify` genuinely non-destructive.
        let incidents: Arc<dyn IncidentStore> = match &staging_pool {
            Some(pool) => Arc::new(PgIncidentStore::new(pool.clone())),
            None => Arc::new(NoWrites),
        };
        let cross_chain: Arc<dyn CrossChainFindingStore> = match &staging_pool {
            Some(pool) => Arc::new(PgIncidentStore::new(pool.clone())),
            None => Arc::new(NoWrites),
        };
        let analytics: Arc<dyn IncidentAnalytics> = match staged_ch {
            Some(client) => Arc::new(ClickhouseAnalytics::new(client)),
            None => Arc::new(NoWrites),
        };

        Ok(Arc::new(SimulationProjector {
            consumer: ProjectionConsumer::new(incidents, analytics, cross_chain),
            _staging_pool: staging_pool,
        }))
    }

    async fn digest_staged(
        &self,
        staging: &Staging,
        _scope: &Scope,
    ) -> Result<ModelDigest, ModelError> {
        // The same fingerprint functions, pointed at the staging namespace.
        let staging_pool = match &self.postgres {
            None => None,
            Some(pg) => Some(
                db::connect_in_schema(pg.url.expose_secret(), staging.id())
                    .await
                    .map_err(|err| {
                        ModelError::wrap(
                            "opening a staging-scoped Postgres pool",
                            std::io::Error::other(err.to_string()),
                        )
                    })?,
            ),
        };
        let staged_ch = self.staged_clickhouse(staging);
        Self::digest_through(staging_pool.as_ref(), staged_ch.as_ref()).await
    }

    async fn promote(&self, staging: &Staging) -> Result<u64, ModelError> {
        let mut rows = 0u64;

        if let Some(pg) = &self.postgres {
            rows += count_postgres(&pg.pool).await?;
            // **Atomic**: Postgres DDL is transactional, so a reader never sees
            // half the tables swapped. The live tables move aside into a
            // `…_superseded` schema rather than being dropped — it is the only
            // copy of any `lost` row and the rollback if this promotion was a
            // mistake. Dropping it is the operator's explicit step.
            let superseded = format!("{}_superseded", staging.id());
            let mut ddl = format!("BEGIN;\nCREATE SCHEMA \"{superseded}\";\n");
            for table in PG_TABLES {
                ddl.push_str(&format!(
                    "ALTER TABLE public.{table} SET SCHEMA \"{superseded}\";\n"
                ));
            }
            for table in PG_TABLES {
                ddl.push_str(&format!(
                    "ALTER TABLE \"{}\".{table} SET SCHEMA public;\n",
                    staging.id()
                ));
            }
            ddl.push_str("COMMIT;\n");
            sqlx::raw_sql(sqlx::AssertSqlSafe(ddl))
                .execute(&pg.pool)
                .await
                .map_err(|err| ModelError::wrap("promoting the Postgres read model", err))?;
            tracing::info!(
                superseded = %superseded,
                "the previous generation is retained; drop it once the promotion is accepted"
            );
        }

        if let (Some(live), Some(staged)) = (&self.clickhouse, self.staged_clickhouse(staging)) {
            rows += count_clickhouse(&staged).await?;
            // **Not atomic across the pair**: `EXCHANGE TABLES` is pairwise, so
            // there is a sub-millisecond window where a dashboard query could
            // read one table swapped and the other not. Stated rather than
            // hidden — these are the trend surface, not the system of record.
            for table in CH_TABLES {
                live.query(&format!(
                    "EXCHANGE TABLES {table} AND \"{}\".{table}",
                    staging.id()
                ))
                .execute()
                .await
                .map_err(|err| ModelError::wrap(format!("promoting {table}"), err))?;
            }
        }

        // The staging namespaces now hold the *old* data (the exchange swapped
        // both ways). Drop the ClickHouse one; the Postgres superseded schema is
        // deliberately kept, above.
        self.discard(staging).await?;
        Ok(rows)
    }

    async fn discard(&self, staging: &Staging) -> Result<(), ModelError> {
        // `IF EXISTS` throughout: discard runs on every failure path, including
        // ones where the staging area was never fully created, and cleanup that
        // fails on an absent object is cleanup nobody can safely retry.
        if let Some(pg) = &self.postgres {
            sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DROP SCHEMA IF EXISTS \"{}\" CASCADE",
                staging.id()
            )))
            .execute(&pg.pool)
            .await
            .map_err(|err| ModelError::wrap("dropping the Postgres staging schema", err))?;
        }
        if let Some(client) = &self.clickhouse {
            client
                .query(&format!("DROP DATABASE IF EXISTS \"{}\"", staging.id()))
                .execute()
                .await
                .map_err(|err| ModelError::wrap("dropping the ClickHouse staging database", err))?;
        }
        Ok(())
    }
}

/// How many rows the Postgres read model holds — one statement over the three
/// tables, so the number is a consistent snapshot rather than three racing
/// counts.
async fn count_postgres(pool: &PgPool) -> Result<u64, ModelError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM incidents)
              + (SELECT count(*) FROM sim_jobs)
              + (SELECT count(*) FROM cross_chain_findings)",
    )
    .fetch_one(pool)
    .await
    .map_err(|err| ModelError::wrap("counting the Postgres read model", err))?;
    Ok(count.max(0) as u64)
}

/// The ClickHouse equivalent. The rollup is counted through the same aggregate
/// its fingerprint uses, so an unmerged `SummingMergeTree` part does not inflate
/// the number.
async fn count_clickhouse(client: &Client) -> Result<u64, ModelError> {
    let analytics: u64 = client
        .query("SELECT count() FROM incident_analytics")
        .fetch_one()
        .await
        .map_err(|err| ModelError::wrap("counting incident_analytics", err))?;
    let rollup: u64 = client
        .query(
            "SELECT count() FROM (SELECT chain FROM incident_timing_rollup \
             GROUP BY chain, severity, slot_of_day)",
        )
        .fetch_one()
        .await
        .map_err(|err| ModelError::wrap("counting incident_timing_rollup", err))?;
    Ok(analytics + rollup)
}

/// Read one column, turning a decode failure into a named [`ModelError`] rather
/// than an opaque sqlx error — a fingerprint that failed on `victim_loss_usd`
/// should say so.
fn get<'r, T>(row: &'r sqlx::postgres::PgRow, column: &str) -> Result<T, ModelError>
where
    T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(column)
        .map_err(|err| ModelError::wrap(format!("reading column `{column}`"), err))
}

fn insert(
    digest: &mut ModelDigest,
    key: String,
    encoded: rebuild::digest::RowDigest,
) -> Result<(), ModelError> {
    digest.insert(key, encoded).map_err(|key| {
        ModelError::new(format!(
            "two rows share the business key `{key}` — the read model's own uniqueness is broken"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_spellings_cover_what_an_operator_would_type() {
        assert_eq!(Targets::parse("incidents"), Some(Targets::Postgres));
        assert_eq!(Targets::parse("postgres"), Some(Targets::Postgres));
        assert_eq!(Targets::parse("dashboards"), Some(Targets::Clickhouse));
        assert_eq!(Targets::parse("analytics"), Some(Targets::Clickhouse));
        assert_eq!(Targets::parse("all"), Some(Targets::All));
        assert_eq!(Targets::parse("everything"), None);
    }

    #[test]
    fn each_target_names_itself_distinctly_for_the_report() {
        let names = [
            Targets::Postgres.name(),
            Targets::Clickhouse.name(),
            Targets::All.name(),
        ];
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
    }

    /// The staging namespace and the promotion must cover the same tables; a
    /// second list would be a way for them to disagree silently.
    #[test]
    fn the_staged_and_promoted_table_lists_are_the_same_list() {
        assert_eq!(PG_TABLES.len(), 3);
        assert!(PG_TABLES.contains(&"incidents"));
        assert!(PG_TABLES.contains(&"sim_jobs"));
        assert!(PG_TABLES.contains(&"cross_chain_findings"));
        assert_eq!(CH_TABLES, ["incident_analytics", "incident_timing_rollup"]);
    }

    /// A rebuild must replay every type the live consumer subscribes to,
    /// otherwise the rebuilt model is missing whatever the omitted type carried.
    #[test]
    fn the_replayed_event_types_are_the_consumed_ones() {
        let projector = SimulationProjector {
            consumer: ProjectionConsumer::new(
                Arc::new(NoWrites),
                Arc::new(NoWrites),
                Arc::new(NoWrites),
            ),
            _staging_pool: None,
        };
        assert_eq!(projector.event_types(), consumed_event_types());
        assert!(projector
            .event_types()
            .contains(&"IncidentCreated".to_string()));
    }

    #[test]
    fn this_model_declares_that_it_only_supports_a_full_rebuild() {
        let model = SimulationReadModel::new(Stores::Clickhouse(Client::default()));
        assert_eq!(model.scope_support(), ScopeSupport::FullOnly);
    }
}
