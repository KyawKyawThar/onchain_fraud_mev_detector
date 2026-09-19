//! The transactional-outbox seam (§20): a customer-facing write and the event
//! that announces it commit **together**, and a background flusher publishes.
//!
//! ```text
//!   request ──► BEGIN
//!                 INSERT the row the customer asked for
//!                 INSERT the announcement envelope  ◄── enqueue()
//!               COMMIT
//!                    │
//!   flusher ─────────┴──► claim a lease ──► publish ──► stamp published_at
//! ```
//!
//! Publishing straight to Kafka after a commit leaves a window where the write
//! happened and the announcement did not; publishing before the commit leaves
//! the opposite. The outbox closes both: the announcement is part of the same
//! transaction as the write, so a crash anywhere loses nothing, and the
//! customer's request never waits on a broker.
//!
//! # Promoted, not invented
//!
//! This is `rule-engine`'s outbox, generalized when the §19 feedback loop
//! needed the same guarantee for the same reason. Two hand-written outboxes
//! would be two sets of answers to "what happens if we crash here", which is
//! the argument the `resilience` retrofit makes about four hand-rolled retry
//! loops. `copilot`'s outbox is deliberately **not** folded in: it drains a
//! domain store of drafts rather than a table of envelopes, and forcing one
//! abstraction over both would describe neither.
//!
//! # At-least-once, with a lease
//!
//! Delivery is at-least-once: a crash between `publish` and the stamp
//! republishes, which every consumer in this platform already tolerates (§4).
//! What the **lease** adds is bounded waste. A horizontally scaled service —
//! the API service runs behind an HPA — would otherwise have every replica
//! draining every pending row, publishing each one N times. A claim marks a
//! batch as taken for a bounded window, so the common case is one publisher
//! per row, and a flusher that dies mid-batch simply loses its claim and
//! another picks the rows up when the lease expires.
//!
//! # The table name is a constant, and that is the whole injection story
//!
//! [`Outbox::new`] takes `&'static str`s. They come from crate constants, are
//! never derived from a request, and the queries are otherwise fully
//! parameterized — which is what lets this crate use the runtime `sqlx` API
//! (a table name cannot be a bind parameter, so `query!` cannot express it)
//! without the usual objection.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use event_bus::EventSink;
use events::EventEnvelope;
use sqlx::{PgExecutor, PgPool, Row};
use tokio_util::sync::CancellationToken;

/// How many pending rows one tick drains at most. These are human-rate writes
/// (a rule created, a verdict submitted); a burst beyond this spills into the
/// next tick rather than holding a lease over a long publish loop.
const BATCH: i64 = 64;

/// How long a claim holds a batch before another flusher may retry it. Long
/// enough to publish 64 events, short enough that a crashed replica's rows are
/// not stranded for a noticeable time.
const LEASE: Duration = Duration::from_secs(30);

/// What an [`Outbox::enqueue`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    /// The announcement is queued and will publish.
    Queued,
    /// An announcement with this idempotency key was already queued, so
    /// nothing was written. The caller's retry is a no-op, not a duplicate.
    AlreadyQueued,
}

/// One outbox table.
#[derive(Debug, Clone, Copy)]
pub struct Outbox {
    table: &'static str,
    metric_prefix: &'static str,
}

impl Outbox {
    /// Bind to a table. Both arguments are compile-time constants owned by the
    /// calling crate — see the module docs on why that matters.
    ///
    /// `metric_prefix` names the counters (`{prefix}_published_total`,
    /// `{prefix}_publish_failures_total`). It is separate from the table name
    /// so a table can be renamed without silently renaming the series a
    /// dashboard and an alert are built on.
    pub const fn new(table: &'static str, metric_prefix: &'static str) -> Self {
        Self {
            table,
            metric_prefix,
        }
    }

    /// Queue an announcement **inside the caller's transaction**.
    ///
    /// Takes an executor rather than a pool precisely so it cannot be called
    /// outside one by accident: the whole guarantee is that this INSERT and
    /// the caller's own write share a commit.
    ///
    /// `idempotency_key` makes a retried request a no-op. `None` queues
    /// unconditionally, which is right for a write that is already keyed by
    /// something unique (a rule id) and wrong for one that is not.
    pub async fn enqueue<'e, E>(
        &self,
        executor: E,
        envelope: &serde_json::Value,
        idempotency_key: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Enqueued>
    where
        E: PgExecutor<'e>,
    {
        let sql = format!(
            "INSERT INTO {} (envelope, idempotency_key, created_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (idempotency_key) DO NOTHING \
             RETURNING id",
            self.table
        );
        // `AssertSqlSafe` is the audit sqlx asks for, and the audit is short:
        // the only interpolation is `self.table`, a `&'static str` from a
        // crate constant. Every value is a bind parameter.
        let queued = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(envelope)
            .bind(idempotency_key)
            .bind(now)
            .fetch_optional(executor)
            .await
            .with_context(|| format!("queueing an announcement in {}", self.table))?;

        Ok(match queued {
            Some(_) => Enqueued::Queued,
            None => Enqueued::AlreadyQueued,
        })
    }

    /// One drain pass: claim up to [`BATCH`] pending rows, publish them in id
    /// order, and stamp each only after its publish succeeds.
    ///
    /// A publish failure stops the pass — order is preserved and the row
    /// retries once its lease expires. An **undecodable** envelope is stamped
    /// published with a loud log instead: it can never succeed, and one poison
    /// row must not wedge the drain (§4's skip-the-poison rule, applied to a
    /// producer).
    pub async fn flush_once(&self, pool: &PgPool, sink: &dyn EventSink) -> Result<u64> {
        let claim_sql = format!(
            "UPDATE {table} SET claimed_until = now() + $1::interval \
             WHERE id IN ( \
                 SELECT id FROM {table} \
                 WHERE published_at IS NULL \
                   AND (claimed_until IS NULL OR claimed_until < now()) \
                 ORDER BY id \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT $2 \
             ) \
             RETURNING id, envelope",
            table = self.table
        );
        // Interpolates `self.table` only — see `enqueue`'s note.
        let rows = sqlx::query(sqlx::AssertSqlSafe(claim_sql))
            .bind(format!("{} seconds", LEASE.as_secs()))
            .bind(BATCH)
            .fetch_all(pool)
            .await
            .with_context(|| format!("claiming pending rows from {}", self.table))?;

        let mut published = 0u64;
        for row in rows {
            let id: i64 = row.try_get("id").context("outbox row without an id")?;
            let raw: serde_json::Value = row
                .try_get("envelope")
                .context("outbox row without an envelope")?;

            let envelope: EventEnvelope = match serde_json::from_value(raw) {
                Ok(envelope) => envelope,
                Err(err) => {
                    tracing::error!(
                        outbox_id = id,
                        table = self.table,
                        error = %err,
                        "outbox row holds an undecodable envelope; marking published to unblock the drain"
                    );
                    self.mark_published(pool, id).await?;
                    continue;
                }
            };

            if let Err(err) = sink.publish(envelope).await {
                metrics::counter!(format!("{}_publish_failures_total", self.metric_prefix))
                    .increment(1);
                tracing::warn!(
                    outbox_id = id,
                    table = self.table,
                    error = %err,
                    "outbox publish failed; row stays pending"
                );
                break;
            }
            self.mark_published(pool, id).await?;
            metrics::counter!(format!("{}_published_total", self.metric_prefix)).increment(1);
            published += 1;
        }
        Ok(published)
    }

    async fn mark_published(&self, pool: &PgPool, id: i64) -> Result<()> {
        let sql = format!(
            "UPDATE {} SET published_at = now(), claimed_until = NULL WHERE id = $1",
            self.table
        );
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(id)
            .execute(pool)
            .await
            .with_context(|| format!("stamping {} row {id} published", self.table))?;
        Ok(())
    }

    /// Drain every `interval` until `shutdown`.
    ///
    /// Errors are logged and retried on the next tick: the flusher itself must
    /// never die to a broker blip, or the outbox silently stops being an
    /// outbox — which looks exactly like a system with nothing to announce.
    pub async fn run_flusher(
        self,
        pool: PgPool,
        sink: Arc<dyn EventSink>,
        interval: Duration,
        shutdown: CancellationToken,
    ) {
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    // One last pass, so a verdict submitted a second before
                    // shutdown is not left waiting for the next boot.
                    if let Err(err) = self.flush_once(&pool, sink.as_ref()).await {
                        tracing::warn!(error = %err, table = self.table, "final outbox flush failed");
                    }
                    tracing::info!(table = self.table, "outbox flusher stopping");
                    return;
                }
                () = tokio::time::sleep(interval) => {}
            }
            match self.flush_once(&pool, sink.as_ref()).await {
                Ok(0) => {}
                Ok(published) => {
                    tracing::debug!(
                        published,
                        table = self.table,
                        "outbox announcements published"
                    )
                }
                Err(err) => {
                    tracing::warn!(error = %err, table = self.table, "outbox flush failed; retrying next tick")
                }
            }
        }
    }
}
