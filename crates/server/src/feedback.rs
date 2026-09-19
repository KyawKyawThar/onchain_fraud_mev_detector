//! `AlertFeedbackRecorded` emission (§19, production-readiness Epic E) — the
//! analyst-feedback half of the false-positive loop.
//!
//! `POST /v1/incidents/{incident_id}/feedback` is the only place in the
//! platform where a *human* tells it that it was wrong. The verdict is written
//! to a **transactional outbox** in the request path and published from there;
//! the simulation service's projection folds it into the feedback ledger, and
//! the §19 false-positive panel — and the SLO alert behind it — read that
//! ledger.
//!
//! # Why an outbox and not a queue
//!
//! The obvious shape is [`crate::usage`]'s and [`crate::audit`]'s: a bounded
//! channel, a background publisher, a dropped record on overflow. Both of
//! those are *metering*, and a dropped metering record is a rounding error in
//! a number nobody bills on.
//!
//! A verdict is not. It is a sample in an accuracy measurement that has very
//! few — a few hundred adjudications is a good month — and the losses are not
//! random: an in-memory queue overflows exactly when the platform is
//! unhealthy, which is exactly when analysts are most likely to be marking
//! incidents noise. The bias runs toward flattering the platform, in the one
//! number whose whole job is to be unflattering.
//!
//! So the request path does one fast `INSERT` into [`FEEDBACK_OUTBOX`] and
//! answers `202`. Kafka's availability becomes the flusher's problem instead
//! of the customer's, and a crash between accepting and publishing loses
//! nothing. What remains a `503` is a *Postgres* outage, where the platform
//! genuinely cannot promise to keep the verdict — and saying so is better than
//! accepting one we would drop.
//!
//! # Idempotency
//!
//! A retry after a timeout must not become a second verdict. The outbox row
//! carries a key derived from the incident, the customer and the caller's own
//! `Idempotency-Key` header when they send one; a repeat is a no-op at the
//! database rather than a duplicate on the backbone.

use async_trait::async_trait;
use events::feedback::AlertFeedbackRecorded;
use events::primitives::Chain;
use events::{DomainEvent, EventEnvelope};
use outbox::{Enqueued, Outbox};
use sqlx::PgPool;

/// Counter: verdicts durably accepted, labelled by verdict, reason code and
/// cohort.
pub const FEEDBACK_RECORDED_TOTAL: &str = "alert_feedback_recorded_total";
/// Counter: submissions refused because the platform could not durably accept
/// them (a Postgres fault). The caller saw a `503` and can retry, so this is
/// not yet a lost sample — but a sustained rate is a loop that is quietly
/// closing.
pub const FEEDBACK_REFUSED_TOTAL: &str = "alert_feedback_refused_total";
/// Counter: retries that were recognised and dropped, rather than becoming a
/// second verdict.
pub const FEEDBACK_DUPLICATE_TOTAL: &str = "alert_feedback_duplicate_total";

/// This service's outbox binding (see [`outbox`]). The publish side is
/// [`Outbox::run_flusher`], spawned in `main`.
pub const FEEDBACK_OUTBOX: Outbox = Outbox::new("feedback_outbox", "feedback_outbox");

/// Where a verdict is durably parked before it reaches the backbone.
///
/// A seam rather than a bare [`Outbox`] for the reason §2 gives generally, and
/// for one specific to this endpoint: the handler's interesting behaviour is
/// what it does when the queue *refuses* — a `503` rather than a comfortable
/// `202` — and a test that can only reach that path by taking Postgres down is
/// a test nobody runs.
#[async_trait]
pub trait FeedbackQueue: Send + Sync {
    /// Park one verdict. `key` deduplicates retries; see
    /// [`idempotency_key`].
    async fn enqueue(&self, envelope: &serde_json::Value, key: &str) -> anyhow::Result<Enqueued>;
}

/// The production queue: the `feedback_outbox` table.
pub struct OutboxQueue {
    pool: PgPool,
}

impl OutboxQueue {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FeedbackQueue for OutboxQueue {
    async fn enqueue(&self, envelope: &serde_json::Value, key: &str) -> anyhow::Result<Enqueued> {
        FEEDBACK_OUTBOX
            .enqueue(&self.pool, envelope, Some(key), chrono::Utc::now())
            .await
    }
}

/// An in-memory stand-in for handler tests: records what was parked, dedups on
/// the same key, and can be told to fail.
#[cfg(any(test, feature = "test-util"))]
pub mod test_util {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct InMemoryFeedbackQueue {
        queued: Mutex<Vec<serde_json::Value>>,
        keys: Mutex<BTreeSet<String>>,
        fail: bool,
    }

    impl InMemoryFeedbackQueue {
        pub fn new() -> Self {
            Self::default()
        }

        /// A queue that cannot accept anything — Postgres down.
        pub fn failing() -> Self {
            Self {
                fail: true,
                ..Self::default()
            }
        }

        /// The envelopes parked so far, in order.
        pub fn queued(&self) -> Vec<serde_json::Value> {
            self.queued.lock().expect("queued lock").clone()
        }
    }

    #[async_trait]
    impl FeedbackQueue for InMemoryFeedbackQueue {
        async fn enqueue(
            &self,
            envelope: &serde_json::Value,
            key: &str,
        ) -> anyhow::Result<Enqueued> {
            if self.fail {
                anyhow::bail!("feedback outbox unavailable");
            }
            if !self.keys.lock().expect("keys lock").insert(key.to_owned()) {
                return Ok(Enqueued::AlreadyQueued);
            }
            self.queued
                .lock()
                .expect("queued lock")
                .push(envelope.clone());
            Ok(Enqueued::Queued)
        }
    }
}

/// The envelope a verdict publishes as.
///
/// Not chain-scoped — an opinion about an incident is not a chain fact — and
/// stamped [`Chain::ETHEREUM`] like the other API-side producers, so the stamp
/// only decides partition placement; the event's own `business_partition_key`
/// keys it by incident instead (`events::DomainEvent::business_partition_key`).
pub fn envelope_for(verdict: AlertFeedbackRecorded) -> EventEnvelope {
    EventEnvelope::new(Chain::ETHEREUM, DomainEvent::AlertFeedbackRecorded(verdict))
}

/// The outbox key that makes a retried submission a no-op.
///
/// Keyed on the *verdict's identity*, not on its content: a customer who
/// changes their mind is submitting a different opinion about the same
/// incident and must not be deduplicated away, so the verdict itself is part
/// of the key. A caller-supplied `Idempotency-Key` narrows it further, which
/// is what makes a network-level retry safe even when the customer is
/// deliberately revising.
pub fn idempotency_key(verdict: &AlertFeedbackRecorded, client_key: Option<&str>) -> String {
    match client_key {
        Some(key) => format!(
            "{}:{}:{}",
            verdict.incident_id.0, verdict.customer_id.0, key
        ),
        None => format!(
            "{}:{}:{}",
            verdict.incident_id.0,
            verdict.customer_id.0,
            verdict.verdict.as_str()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use events::feedback::{FeedbackCohort, FeedbackReason, FeedbackVerdict};
    use events::primitives::{CustomerId, IncidentId};

    fn verdict(v: FeedbackVerdict) -> AlertFeedbackRecorded {
        AlertFeedbackRecorded {
            incident_id: IncidentId(uuid::Uuid::from_u128(0x1c)),
            customer_id: CustomerId(uuid::Uuid::from_u128(0xc0)),
            verdict: v,
            reason_code: FeedbackReason::OurOwnActivity,
            reason: Some("our own rebalancer".into()),
            cohort: FeedbackCohort::Volunteered,
            submitted_at: Utc::now(),
        }
    }

    #[test]
    fn a_verdict_is_keyed_by_the_incident_and_not_by_its_clock() {
        // Two submissions of the same opinion, a minute apart: the second is
        // a retry, not a second data point.
        let mut later = verdict(FeedbackVerdict::FalsePositive);
        later.submitted_at = Utc::now() + chrono::Duration::minutes(1);
        assert_eq!(
            idempotency_key(&verdict(FeedbackVerdict::FalsePositive), None),
            idempotency_key(&later, None)
        );
    }

    #[test]
    fn changing_your_mind_is_not_a_duplicate() {
        assert_ne!(
            idempotency_key(&verdict(FeedbackVerdict::FalsePositive), None),
            idempotency_key(&verdict(FeedbackVerdict::TruePositive), None),
            "a revised verdict must reach the ledger, where the later \
             submission supersedes the earlier one"
        );
    }

    #[test]
    fn a_client_key_makes_even_a_revision_retryable() {
        // With a caller-supplied key, two *identical* requests collapse even
        // though they carry different verdicts from different attempts — the
        // caller is asserting "this is the same submission".
        let a = idempotency_key(&verdict(FeedbackVerdict::FalsePositive), Some("abc"));
        let b = idempotency_key(&verdict(FeedbackVerdict::TruePositive), Some("abc"));
        assert_eq!(a, b);
    }

    #[test]
    fn the_envelope_is_keyed_by_its_incident() {
        let envelope = envelope_for(verdict(FeedbackVerdict::FalsePositive));
        assert_eq!(envelope.event_type(), "AlertFeedbackRecorded");
        assert_eq!(
            envelope.partition_key().to_string(),
            uuid::Uuid::from_u128(0x1c).to_string(),
            "a verdict must be keyed by its incident, not by the envelope's chain"
        );
    }
}
