//! Ingestion service (§5) — chain data into the event backbone, reorg-aware.
//!
//! Sprint 2 builds this crate in four slices: **(task 1) the source adapter
//! layer** — the health-checked, circuit-broken RPC failover pool
//! ([`source::rpc::RpcFailoverPool`]) behind the [`source::ChainSource`] seam,
//! feeding an ordered head stream ([`source::head_stream`]); **(task 2) the
//! in-memory reorg-aware [`tree::BlockTree`]** — turns observed heads into
//! canonical/reverted/finalized decisions, bounded by finalization depth; then
//! (tasks 3–4) the `RawBlockReceived`/`BlockAssembled`/… event emission and the
//! source-driven reorg walk on top of the [`tree::AddOutcome`] seam.

pub mod config;
pub mod source;
pub mod tree;
