//! Predictive pipeline service (§16) — a separate binary on a different
//! latency regime (target < block time) from the block-based fast/slow
//! paths: `MempoolSource → decode → predict-engine → PredictedAlert`, scored
//! against intelligence's cached entity labels.
//!
//! - [`source`] — the mempool source adapter: a single RPC endpoint polled
//!   for pending transactions.
//! - [`decode`] — decodes a pending tx's calldata into the same decoded-
//!   action shapes `detection` models (`detector_api::enrichment`).
//! - [`intel_client`] — the gRPC read into intelligence's cached labels.
//! - [`predict`] — the predict-engine: scores decoded actions against those
//!   labels into a forecast.
//!
//! Sprint 16 (§16.1) adds a second, independent pipeline sharing this binary —
//! a lending-protocol **position tracker**, the platform's first cross-block
//! *predictive* writer:
//!
//! - [`lending_decode`] — decodes an Aave/Compound event log into a
//!   [`lending_decode::LendingEvent`].
//! - [`position`] — [`position::PositionTracker`], the reorg-versioned
//!   `(protocol, account)` position book a later cascade-engine stage (Sprint
//!   16 task 2) reads to compute liquidation risk.
//! - [`position_source`] — fetches one canonical block's lending logs via
//!   `eth_getLogs`.
//! - [`position_consumer`] — folds `BlockCanonicalized`/`BlockReverted` into the
//!   tracker over the shared `event_bus::run_consumer` loop.
//!
//! Sprint 16 task 2 (§16.2) adds the cascade engine, driven by its own
//! ticker-based price source rather than block cadence (oracle updates aren't
//! block-aligned, and this pipeline targets sub-block latency):
//!
//! - [`price_source`] — polls configured Chainlink-style feeds and reports
//!   only genuine `updatedAt` advances as [`price_source::PriceTick`]s.
//! - [`cascade`] — [`cascade::CascadeEngine`], which recomputes health
//!   factors off [`position::PositionTracker::current`] on every price tick
//!   and reports positions whose risk band has worsened.

mod abi_words;
pub mod cascade;
pub mod config;
pub mod decode;
pub mod intel_client;
pub mod lending_decode;
pub mod position;
pub mod position_consumer;
pub mod position_source;
pub mod predict;
pub mod price_source;
pub mod source;
