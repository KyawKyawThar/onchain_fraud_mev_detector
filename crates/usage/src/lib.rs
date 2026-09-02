//! Usage service (§13, trimmed to the Sprint-12 scope): the Kafka sink that
//! drains `UsageRecorded` from every metering producer (api today;
//! notification/ingestion as t2 wires them) into the append-only ClickHouse
//! `usage_events` table, for analytics, capacity planning and abuse detection.
//!
//! **Deliberately not a billing service.** The §13 Postgres side — accounts,
//! plans, billing periods, aggregates — is descoped (2026-07-17 product
//! decision: all features to all users, no tiers, no Stripe). What remains is
//! the raw-events substrate a billing layer would aggregate over if
//! monetization ever lands. This sink consumes and stores; it emits nothing
//! and gates nothing.
//!
//! Structure mirrors the event store (the other Kafka→ClickHouse sink):
//! - [`config`] — env resolved once at boot, fail fast.
//! - [`migrate`] — the shared `ch-migrate` runner bound to this service's own
//!   `usage_schema_migrations` bookkeeping table (§14: no shared tables).
//! - [`store`] — the one write path ([`store::UsageStore::insert`]) and the
//!   envelope→row projection.
//! - [`kafka`] — the at-least-once consume loop over the shared `event-bus`
//!   seam; commit only after a successful insert.
//! - [`budget`] — per-customer token budget **alarms** (§20.4, Sprint 20 t5):
//!   the read side of the same stream, telling a human when one customer's LLM
//!   spend has gone somewhere nobody expected.
//!
//! # It still gates nothing
//!
//! [`budget`] does not change that. It raises alarms and writes log lines; it
//! never refuses a call, and there is no per-customer quota anywhere in this
//! platform — the only enforced ceiling is `llm::admission`'s platform-wide
//! runaway-loop valve. An alarm is a sentence addressed to an operator, and
//! this crate is still a sink that "consumes and stores".

/// The §2 fields this service reads, declared so the schema registry can hold
/// them (§17).
///
/// The registry gate in `events` can prove a field was removed; it cannot know
/// *who* was reading it, because the dependency points the other way. This is
/// the other end of that: the same shape as
/// [`events::topics_for`], which makes a consumer declare the event types it
/// subscribes to and validates the list against the schema. A field removed out
/// from under this sink then fails *this crate's* test, naming itself, instead
/// of turning into a `NULL` column nobody notices for a month.
///
/// Every entry is a field [`store::UsageRow`] actually projects.
pub const EVENT_READS: &[(&str, &str)] = &[
    ("UsageRecorded", "customer_id"),
    ("UsageRecorded", "event_type"),
    ("UsageRecorded", "quantity"),
    ("UsageRecorded", "timestamp"),
];

pub mod budget;
pub mod config;
pub mod kafka;
pub mod migrate;
pub mod store;

#[cfg(test)]
mod schema_contract {
    #[test]
    fn declared_reads_still_exist_in_the_committed_schema() {
        events::schema::assert_reads("usage", super::EVENT_READS);
    }
}
