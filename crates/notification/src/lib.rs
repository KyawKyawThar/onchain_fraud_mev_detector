//! Notification service (§11, Sprint 12 t4): severity-routed delivery over
//! webhook/email/Slack/PagerDuty, with retry/backoff, dedup per incident per
//! subscriber, delivery receipts, and the provisional → confirmed →
//! retracted lifecycle paired to the original alert.
//!
//! Module map:
//! * [`model`] — the subscriber side: who gets notified, on which channels,
//!   gated by which filter.
//! * `notice` — the event side: what gets sent, derived deterministically
//!   from one consumed [`events::EventEnvelope`].
//! * `delivery` — the [`delivery::ChannelSink`] seam + the production
//!   HTTP/SMTP adapters.
//! * `store` — the Postgres [`store::NotificationStore`] seam: subscribers,
//!   the delivery/dedup ledger, the incident↔alert correlation index.
//! * `subscriber_cache` — the [`subscriber_cache::SubscriberSetHandle`]
//!   snapshot every consumed event routes against, so the hot path never
//!   hits Postgres per event (mirrors `rule_engine::compile::RuleSetHandle`).
//! * `consumer` — the imperative shell tying the above together over
//!   `event_bus::run_consumer`.
//! * `config` — env-resolved runtime configuration (see `src/main.rs`).
//!
//! Production is Postgres + real HTTP/SMTP; tests use the in-memory doubles
//! behind the `test-util` feature (mirrors `rule_engine::test_util`).

/// The §2 fields this service reads, declared so the schema registry can hold
/// them (§17).
///
/// The registry gate in `events` can prove a field was removed; it cannot know
/// *who* was reading it, because the dependency points the other way. This is
/// the other end of that — the same shape as [`events::topics_for`], which makes
/// a consumer declare the event types it subscribes to and validates the list
/// against the schema. A field removed out from under this consumer then fails
/// *this crate's* test, naming itself, rather than silently dropping a
/// notification's severity or its recipient.
///
/// Routing, dedup and correlation only: fields a [`notice::Notice`] or the
/// lifecycle correlation is actually built from.
pub const EVENT_READS: &[(&str, &str)] = &[
    // The provisional → confirmed → retracted lifecycle (§6, §7).
    ("PreliminaryAlertCreated", "alert_id"),
    ("PreliminaryAlertCreated", "addresses"),
    ("PreliminaryAlertCreated", "kind"),
    ("PreliminaryAlertCreated", "confidence"),
    ("PreliminaryAlertCreated", "severity"),
    ("PreliminaryAlertCreated", "suggested_action"),
    ("IncidentCreated", "incident_id"),
    ("IncidentCreated", "alert_id"),
    ("IncidentCreated", "severity"),
    ("IncidentCreated", "suggested_action"),
    ("IncidentRetracted", "incident_id"),
    ("IncidentRetracted", "reason"),
    ("IncidentFinalized", "incident_id"),
    // Customer-owned rule alerts (§9) and the §25 exposure digest.
    ("RuleAlertCreated", "alert_id"),
    ("RuleAlertCreated", "address"),
    ("RuleAlertCreated", "owner"),
    ("RuleAlertCreated", "explanation"),
];

pub mod config;
pub mod consumer;
pub mod delivery;
pub mod email_delivery;
pub mod http_delivery;
pub mod model;
pub mod notice;
pub mod sink;
pub mod store;
pub mod subscriber_cache;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

#[cfg(test)]
mod schema_contract {
    #[test]
    fn declared_reads_still_exist_in_the_committed_schema() {
        events::schema::assert_reads("notification", super::EVENT_READS);
    }
}
