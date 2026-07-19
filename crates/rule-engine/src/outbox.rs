//! The transactional-outbox flusher (§20) — the publish half of
//! [`RuleStore::create_rule_announced`](crate::store::RuleStore::create_rule_announced).
//!
//! POST /v1/rules writes the rule row **and** its `RuleCreated` announcement
//! (a full wire-form [`EventEnvelope`]) in one Postgres transaction; this task
//! drains the pending announcements onto Kafka. The split is what makes the
//! dual write safe: a crash after commit but before publish loses nothing —
//! the row is still pending and the next tick publishes it. Delivery is
//! therefore **at-least-once** (crash between publish and the
//! `published_at` stamp republishes), which the consumer side already
//! tolerates: a duplicate `RuleCreated` just re-triggers an idempotent rule
//! refresh.
//!
//! Pending rows drain oldest-first, and a publish failure stops the batch —
//! order is preserved and the failed row retries next tick. Published rows
//! are stamped, not deleted (audit: what did we announce, when), which the
//! partial index on `published_at IS NULL` keeps free.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use event_bus::EventSink;
use events::EventEnvelope;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

/// Counter: announcements published off the outbox.
pub const OUTBOX_PUBLISHED_TOTAL: &str = "rule_outbox_published_total";
/// Counter: publish attempts that failed (the row stays pending — alert on a
/// sustained rate, it means Kafka is rejecting the announcements).
pub const OUTBOX_PUBLISH_FAILURES_TOTAL: &str = "rule_outbox_publish_failures_total";

/// How many pending rows one tick drains at most. Rule creation is a human
/// action — a burst beyond this just spills into the next tick.
const BATCH: i64 = 64;

/// Drain the outbox every `interval` until `shutdown`. Errors are logged and
/// retried on the next tick — the flusher itself must never die to a broker
/// blip, or the outbox silently stops being an outbox.
pub async fn run_flusher(
    pool: PgPool,
    sink: Arc<dyn EventSink>,
    interval: Duration,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                tracing::info!("outbox flusher stopping");
                return;
            }
            () = tokio::time::sleep(interval) => {}
        }
        match flush_once(&pool, sink.as_ref()).await {
            Ok(0) => {}
            Ok(published) => tracing::debug!(published, "outbox announcements published"),
            Err(err) => tracing::warn!(error = %err, "outbox flush failed; retrying next tick"),
        }
    }
}

/// One drain pass: publish up to [`BATCH`] pending announcements in id order,
/// stamping each `published_at` only after its publish succeeds. Returns how
/// many were published. A publish failure stops the pass (order preserved;
/// the row retries next tick).
pub async fn flush_once(pool: &PgPool, sink: &dyn EventSink) -> Result<u64> {
    let rows = sqlx::query!(
        r#"SELECT id, envelope AS "envelope: serde_json::Value"
           FROM rule_outbox
           WHERE published_at IS NULL
           ORDER BY id
           LIMIT $1"#,
        BATCH,
    )
    .fetch_all(pool)
    .await
    .context("reading pending outbox rows")?;

    let mut published = 0u64;
    for row in rows {
        let envelope: EventEnvelope = match serde_json::from_value(row.envelope) {
            Ok(envelope) => envelope,
            Err(err) => {
                // A malformed envelope can never publish: stamp it (with a
                // loud log) so it can't wedge the drain — the row itself is
                // the audit trail of what was mis-written.
                tracing::error!(
                    outbox_id = row.id,
                    error = %err,
                    "outbox row holds an undecodable envelope; marking published to unblock the drain"
                );
                mark_published(pool, row.id).await?;
                continue;
            }
        };
        if let Err(err) = sink.publish(envelope).await {
            metrics::counter!(OUTBOX_PUBLISH_FAILURES_TOTAL).increment(1);
            tracing::warn!(
                outbox_id = row.id,
                error = %err,
                "outbox publish failed; row stays pending"
            );
            break;
        }
        mark_published(pool, row.id).await?;
        metrics::counter!(OUTBOX_PUBLISHED_TOTAL).increment(1);
        published += 1;
    }
    Ok(published)
}

async fn mark_published(pool: &PgPool, id: i64) -> Result<()> {
    sqlx::query!(
        "UPDATE rule_outbox SET published_at = now() WHERE id = $1",
        id,
    )
    .execute(pool)
    .await
    .with_context(|| format!("stamping outbox row {id} published"))?;
    Ok(())
}
