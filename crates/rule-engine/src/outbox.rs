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
//!
//! # This module is now a binding, not an implementation
//!
//! The mechanics moved to [`outbox`] when the §19 feedback loop needed the
//! same guarantee (readiness Epic E): two hand-written outboxes would be two
//! sets of answers to "what happens if we crash here". What stays here is the
//! *binding* — which table, which metric names — because those are this
//! service's facts, and because a shared crate that also owned the metric
//! names could rename a dashboard's series from another crate's changelog.
//!
//! One behaviour did change: the drain now takes a **lease** on the rows it
//! claims, so two rule-engine replicas no longer each publish every pending
//! announcement.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use event_bus::EventSink;
use outbox::Outbox;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

/// Counter: announcements published off the outbox.
pub const OUTBOX_PUBLISHED_TOTAL: &str = "rule_outbox_published_total";
/// Counter: publish attempts that failed (the row stays pending — alert on a
/// sustained rate, it means Kafka is rejecting the announcements).
pub const OUTBOX_PUBLISH_FAILURES_TOTAL: &str = "rule_outbox_publish_failures_total";

/// This service's outbox: the `rule_outbox` table, publishing under the metric
/// names above. `const` so the binding is one value, not a construction every
/// call site repeats.
pub const RULE_OUTBOX: Outbox = Outbox::new("rule_outbox", "rule_outbox");

/// Drain the outbox every `interval` until `shutdown`.
pub async fn run_flusher(
    pool: PgPool,
    sink: Arc<dyn EventSink>,
    interval: Duration,
    shutdown: CancellationToken,
) {
    RULE_OUTBOX
        .run_flusher(pool, sink, interval, shutdown)
        .await
}

/// One drain pass. Returns how many announcements were published.
pub async fn flush_once(pool: &PgPool, sink: &dyn EventSink) -> Result<u64> {
    RULE_OUTBOX.flush_once(pool, sink).await
}
