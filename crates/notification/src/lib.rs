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
