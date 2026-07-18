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

pub mod config;
pub mod decode;
pub mod intel_client;
pub mod predict;
pub mod source;
