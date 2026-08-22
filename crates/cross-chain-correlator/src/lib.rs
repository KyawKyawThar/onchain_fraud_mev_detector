//! Cross-chain MEV correlator (§17, §24, Sprint 17 t1) — bridge MEV and
//! cross-chain arbitrage only exist *across* chains, so this is the one
//! consumer in the workspace whose job is to hold every monitored chain's
//! event stream in one process rather than filtering foreign chains away.
//!
//! ```text
//! chain A stream ─┐   chain_consumer::ChainConsumer (one task per chain,
//! chain B stream ─┼─►  own consumer group, foreign-chain records committed
//! chain C stream ─┘   as no-ops) ──► router::LegRouter ──► one
//!                                     actor::CorrelationActor per
//!                                     configured bridge/pair, each owning a
//!                                     buffer::CandidateLegBuffer
//! ```
//!
//! ## Scope of this pass (Sprint 17 task 1)
//!
//! This crate wires the skeleton the sprint plan names: the per-chain
//! consumers, the per-bridge/pair correlation actors, and the bounded,
//! time-window-evicted candidate-leg buffer — the cross-chain analogue of
//! [`detector_api::CrossBlockState`], windowed on wall-clock **observation
//! time** rather than block count (chains have different block times and
//! finality, §24), with the same memory-DoS discipline as
//! `simulation::cache`/`simulation::reorg::OrphanedBlocks`.
//!
//! What this pass deliberately does **not** do: [`leg::StubExtractor`], the
//! [`leg::LegExtractor`] `main.rs` wires in today, always returns `None`.
//! Neither a `BridgeDeposit` domain event nor per-tx enrichment exists on the
//! live chain-event stream yet, and the real leg shape is tied to the
//! join-key design — both land together in Sprint 17 task 2 ("windowed join
//! on a behaviour-derived key"), which plugs in its own [`leg::LegExtractor`]
//! at the wiring site without touching [`chain_consumer::ChainConsumer`]
//! itself. Task 3 adds cross-chain finality/reorg handling; task 4 wires
//! findings into intelligence. See `sprint_plan.md`'s Sprint 17 row and
//! `docs/onchain_mev_detector_v2_microservices_rev2.md` §17/§24.

pub mod actor;
pub mod buffer;
pub mod chain_consumer;
pub mod config;
pub mod leg;
pub mod metrics;
pub mod router;
