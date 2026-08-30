//! The transactional-outbox flusher (§20) — the publish half of the landing
//! transaction in [`crate::store`].
//!
//! A draft reaching `ready` writes its row **and** its
//! `IncidentNarrativeDrafted` envelope in one Postgres transaction; this task
//! drains the pending envelopes onto Kafka. The split is what makes the dual
//! write safe: a crash after commit but before publish loses nothing — the row
//! is still pending and the next tick publishes it.
//!
//! Delivery is therefore **at-least-once** (a crash between publish and the
//! `published_at` stamp republishes), which is the right side to fail on for
//! an audit record: a duplicate `IncidentNarrativeDrafted` is two rows naming
//! the same `draft_id`, which any reader can collapse, while a *lost* one is a
//! narrative that exists with no record that it was ever produced.
//!
//! This is deliberately the same mechanism, in the same shape, as
//! `rule_engine::outbox` — one pattern for "a store write and its announcement
//! must be atomic", not two.
//!
//! # Ordering and head-of-line blocking
//!
//! Pending rows drain oldest-first and a publish failure **stops the batch**:
//! the failed row stays pending and retries next tick. That trades throughput
//! for order, which is the correct trade here — these events are keyed by
//! incident, and a reader replaying them wants the drafting record for an
//! incident before any later record about the same one.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use chrono::Utc;
use event_bus::EventSink;
use events::EventEnvelope;
use tokio_util::sync::CancellationToken;

use crate::store::DraftOutbox;

/// Counter: announcements published off the outbox.
pub const OUTBOX_PUBLISHED_TOTAL: &str = "copilot_outbox_published_total";

/// Counter: publish attempts that failed (the row stays pending — alert on a
/// sustained rate, it means Kafka is rejecting the announcements and the audit
/// trail is falling behind the drafts table).
pub const OUTBOX_PUBLISH_FAILURES_TOTAL: &str = "copilot_outbox_publish_failures_total";

/// Gauge: envelopes waiting to publish. The one number that says whether the
/// event stream and the store agree; a rising floor means the flusher is not
/// keeping up (or is wedged on a row it cannot publish).
pub const OUTBOX_PENDING: &str = "copilot_outbox_pending";

/// How many pending rows one tick drains at most. A narrative lands every few
/// minutes at most, so this only matters when draining a backfill's worth of
/// announcements; a burst beyond it spills into the next tick.
const BATCH: i64 = 64;

/// Drain the outbox every `interval` until `shutdown`.
///
/// Errors are logged and retried on the next tick — the flusher itself must
/// never die to a broker blip, or the outbox silently stops being an outbox.
pub async fn run_flusher(
    store: Arc<dyn DraftOutbox>,
    sink: Arc<dyn EventSink>,
    interval: Duration,
    shutdown: CancellationToken,
) {
    loop {
        match flush_once(store.as_ref(), sink.as_ref()).await {
            Ok(0) => {}
            Ok(published) => tracing::debug!(published, "narrative announcements published"),
            Err(err) => tracing::warn!(error = %err, "outbox flush failed; retrying next tick"),
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                // One last drain: a narrative that landed during the shutdown
                // window is already paid for, and announcing it costs a
                // publish.
                if let Err(err) = flush_once(store.as_ref(), sink.as_ref()).await {
                    tracing::warn!(error = %err, "final outbox flush failed; rows stay pending");
                }
                tracing::info!("copilot outbox flusher stopping");
                return;
            }
            () = tokio::time::sleep(interval) => {}
        }
    }
}

/// Publish one batch of pending announcements. Returns how many were sent.
pub async fn flush_once(store: &dyn DraftOutbox, sink: &dyn EventSink) -> Result<u64> {
    let pending = store
        .pending_announcements(BATCH)
        .await
        .context("reading pending outbox rows")?;

    let mut published = 0u64;
    for row in pending {
        let envelope: EventEnvelope = match serde_json::from_value(row.envelope) {
            Ok(envelope) => envelope,
            Err(err) => {
                // A malformed envelope can never publish: stamp it (with a
                // loud log) so it cannot wedge the drain — the row itself
                // remains the audit trail of what was mis-written.
                tracing::error!(
                    outbox_id = row.id,
                    error = %err,
                    "outbox row holds an undecodable envelope; marking published to unblock the drain"
                );
                store.mark_announced(row.id, Utc::now()).await?;
                continue;
            }
        };
        if let Err(err) = sink.publish(envelope).await {
            metrics::counter!(OUTBOX_PUBLISH_FAILURES_TOTAL).increment(1);
            tracing::warn!(
                outbox_id = row.id,
                error = %err,
                "announcement publish failed; row stays pending"
            );
            break;
        }
        store.mark_announced(row.id, Utc::now()).await?;
        metrics::counter!(OUTBOX_PUBLISHED_TOTAL).increment(1);
        published += 1;
    }

    // Published after the drain, so the gauge reflects the backlog this tick
    // could not clear rather than the one it started with.
    if let Ok(pending) = store.pending_announcement_count().await {
        metrics::gauge!(OUTBOX_PENDING).set(pending as f64);
    }
    Ok(published)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{DraftAttempt, DraftOutbox, DraftQueue, DraftWorkQueue};
    use crate::test_util::{completion, InMemoryDraftStore};
    use event_bus::test_util::RecordingSink;
    use event_bus::PublishError;
    use events::primitives::{Chain, IncidentId};
    use events::DomainEvent;
    use llm::cache::CacheKey;

    /// A sink that always refuses — a broker outage, in one type.
    #[derive(Debug, Default)]
    struct FailingSink;

    #[async_trait::async_trait]
    impl EventSink for FailingSink {
        async fn publish(&self, _envelope: EventEnvelope) -> Result<(), PublishError> {
            Err(PublishError::Delivery("broker unavailable".into()))
        }
    }

    /// Land one grounded narrative, which files its announcement in the same
    /// call the way the landing transaction does.
    async fn landed(store: &InMemoryDraftStore) -> uuid::Uuid {
        let event_id = uuid::Uuid::from_u128(0x5A);
        let job = crate::model::DraftJob::narrative(IncidentId::new(), Chain::ETHEREUM);
        store.enqueue(&job, Utc::now()).await.unwrap();
        let claimed = store
            .claim_batch(
                crate::model::DraftKind::ALL,
                1,
                Duration::from_secs(60),
                3,
                Utc::now(),
            )
            .await
            .unwrap();
        let draft_id = claimed[0].job.draft_id;
        store
            .begin_attempt(
                draft_id,
                &CacheKey::new("claude-opus-5", &crate::test_util::request()),
                Some(crate::prompts::incident_narrative()),
                &[event_id],
                Utc::now(),
            )
            .await
            .unwrap();
        store
            .finish(
                draft_id,
                crate::store::DraftOutcome::Completed(Box::new(completion(&format!(
                    "The attacker's transaction preceded the victim's swap [{event_id}]."
                )))),
                Utc::now(),
            )
            .await
            .unwrap();
        draft_id.0
    }

    #[tokio::test]
    async fn a_pending_announcement_publishes_once_and_is_stamped() {
        let store = Arc::new(InMemoryDraftStore::default());
        let sink = RecordingSink::default();
        let draft_id = landed(&store).await;

        assert_eq!(store.pending_announcement_count().await.unwrap(), 1);
        assert_eq!(flush_once(store.as_ref(), &sink).await.unwrap(), 1);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        let DomainEvent::IncidentNarrativeDrafted(event) = &events[0] else {
            panic!("expected IncidentNarrativeDrafted, got {:?}", events[0]);
        };
        assert_eq!(event.draft_id, draft_id);

        // Stamped, so a second tick publishes nothing — the at-least-once
        // window is a crash between publish and stamp, not every tick.
        assert_eq!(flush_once(store.as_ref(), &sink).await.unwrap(), 0);
        assert_eq!(sink.events().len(), 1);
        assert_eq!(store.pending_announcement_count().await.unwrap(), 0);
    }

    /// A broker outage must leave the row pending, not drop the announcement:
    /// the whole point of the outbox is that the audit trail catches up.
    #[tokio::test]
    async fn a_failed_publish_leaves_the_row_pending() {
        let store = Arc::new(InMemoryDraftStore::default());
        landed(&store).await;

        assert_eq!(flush_once(store.as_ref(), &FailingSink).await.unwrap(), 0);
        assert_eq!(
            store.pending_announcement_count().await.unwrap(),
            1,
            "a publish that failed must not be stamped"
        );

        let sink = RecordingSink::default();
        assert_eq!(flush_once(store.as_ref(), &sink).await.unwrap(), 1);
        assert_eq!(sink.events().len(), 1);
    }
}
