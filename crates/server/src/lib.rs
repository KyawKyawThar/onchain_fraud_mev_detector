//! The public §11 API service — library half. `main.rs` is a thin shell that
//! wires these together: [`config`] resolves env once at boot, [`auth`] gates
//! every `/v1` route with JWT bearer verification, [`intelligence_client`] is
//! the gRPC channel into `intelligence`'s `IntelligenceRead` service,
//! [`upstream`] proxies event-store's/simulation-projection's existing
//! internal read endpoints, [`stream`] is the Kafka consumer feeding
//! `WS /v1/stream`'s alert lifecycle, [`usage`] meters every authenticated
//! call as a `UsageRecorded` event (§13), [`metrics`] records the request
//! p50/p99 panel (§19), [`screen`] is the counterparty-screening decision
//! layer behind `POST /v1/address/{addr}/screen` (§11, Sprint 14),
//! [`policy_store`] is the customer-authored decision-policy store the
//! screening layer's named policies resolve against beyond the built-in
//! catalog (Sprint 14 t2), and [`http`] assembles the whole router.
//!
//! Keeping this in a library (mirrors `event-store`) is what lets the router/
//! auth tests exercise the real types without a running process.

pub mod auth;
pub mod config;
pub mod http;
pub mod intelligence_client;
pub mod metrics;
pub mod policy_store;
pub mod screen;
pub mod stream;
pub mod upstream;
pub mod usage;
