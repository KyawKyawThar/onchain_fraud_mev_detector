//! Event-store service (§4) — the immutable system of record.
//!
//! Library half of the crate: the storage core ([`store`]), the read path over
//! it ([`query`] — the §4 query API and §18 replay source), plus the two ingress
//! adapters that feed it — the internal HTTP append API ([`http`]) and the Kafka
//! consumer ([`kafka`]) — wired together by [`config`], [`migrate`] and
//! [`retention`] (the regulatory evidence window, enforced on the table's TTL).
//! The `event-store` binary (`main.rs`) is a thin shell over these; keeping them in a
//! library is what lets the integration tests in `tests/` exercise the real
//! `EventStore` against a throwaway ClickHouse/Kafka.

pub mod config;
pub mod http;
pub mod kafka;
pub mod metrics;
pub mod migrate;
pub mod query;
// The regulatory evidence window (engineering conventions §18), enforced on
// the `events` table's ClickHouse TTL.
pub mod retention;
pub mod store;
