//! Event-store service (§4) — the immutable system of record.
//!
//! Library half of the crate: the storage core ([`store`]) plus the two ingress
//! adapters that feed it — the internal HTTP append API ([`http`]) and the Kafka
//! consumer ([`kafka`]) — wired together by [`config`] and [`migrate`]. The
//! `event-store` binary (`main.rs`) is a thin shell over these; keeping them in a
//! library is what lets the integration tests in `tests/` exercise the real
//! `EventStore` against a throwaway ClickHouse/Kafka.

pub mod config;
pub mod http;
pub mod kafka;
pub mod migrate;
pub mod store;
