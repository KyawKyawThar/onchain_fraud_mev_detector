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
//!
//! Sprint 16 task 3 (§16.3) adds the reflexivity model, driven off the same
//! price tick as the cascade engine:
//!
//! - [`reflexivity`] — [`reflexivity::detect_cascade`], a degree-bounded walk
//!   over the position graph (§8.2's hub-node cap, mirrored) that reports
//!   `LiquidationCascadeWarned` when liquidating the at-risk set would itself
//!   move a mark price into more positions.
//! - [`metrics`] — [`metrics::record_cascade_walk`], the walk-rate/hub-cap/
//!   warning-rate counters recorded at `detect_cascade`'s single call site.
//!
//! Sprint 16 task 4 (§16.4) adds the internal read API:
//!
//! - [`http`] — live position/risk reads and a cascade what-if simulator
//!   over the shared position tracker/cascade engine, Swagger-documented so
//!   the pipeline is directly testable via Postman/Swagger UI, not just Kafka.
//!
//! Sprint 16 task 4 (§16.4/§19) also closes the loop on this whole pipeline:
//! predictive events already publish on their own `mev.events.<EventType>`
//! topics (§2 — one topic per type, opt-in for a consumer with no coupling
//! to the incident stream), so what's left is measuring them and routing
//! them —
//!
//! - [`metrics`] (extended) — [`metrics::record_prediction`], the §19
//!   prediction-rate counter, alongside the existing cascade-walk metrics.
//! - [`lead_time`] — [`lead_time::LeadTimeTracker`], pairing a
//!   `LiquidationRiskPredicted` forecast with the real liquidation it warned
//!   about, feeding [`metrics::record_liquidation_lead_time`] (§19's
//!   lead-time-to-actual-liquidation accuracy signal).
//! - `notification` consumes these topics on its own opt-in consumer task
//!   (never the incident-stream one) and routes them to risk-desk
//!   subscribers filtered on `AlertKind::Liquidation`.

mod abi_words;
pub mod cascade;
pub mod config;
pub mod decode;
pub mod http;
pub mod intel_client;
pub mod lead_time;
pub mod lending_decode;
pub mod metrics;
pub mod position;
pub mod position_consumer;
pub mod position_source;
pub mod predict;
pub mod price_source;
pub mod reflexivity;
pub mod source;
