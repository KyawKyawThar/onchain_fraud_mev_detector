//! Ingestion service (§5) — chain data into the event backbone, reorg-aware.
//!
//! Sprint 2 builds this crate in four slices: **(task 1, here) the source
//! adapter layer** — the health-checked, circuit-broken RPC failover pool
//! ([`source::rpc::RpcFailoverPool`]) behind the [`source::ChainSource`] seam,
//! feeding an ordered head stream ([`source::head_stream`]); then (tasks 2–4)
//! the reorg-aware block tree, the `RawBlockReceived`/`BlockAssembled`/… event
//! emission, and reorg handling on top of it.

pub mod config;
pub mod source;
