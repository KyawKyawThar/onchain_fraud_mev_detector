//! The public §11 API service — library half. `main.rs` is a thin shell that
//! wires these together: [`config`] resolves env once at boot, [`auth`] gates
//! every `/v1` route with JWT bearer verification, [`intelligence_client`] is
//! the gRPC channel into `intelligence`'s `IntelligenceRead` service,
//! [`upstream`] proxies event-store's/simulation-projection's existing
//! internal read endpoints, [`stream`] is the Kafka consumer feeding
//! `WS /v1/stream`'s alert lifecycle, [`usage`] meters every authenticated
//! call as a `UsageRecorded` event (§13), and [`http`] assembles the whole
//! router.
//!
//! Keeping this in a library (mirrors `event-store`) is what lets the router/
//! auth tests exercise the real types without a running process.

pub mod auth;
pub mod config;
pub mod http;
pub mod intelligence_client;
pub mod stream;
pub mod upstream;
pub mod usage;
