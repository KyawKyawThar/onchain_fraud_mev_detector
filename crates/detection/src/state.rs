//! Reorg-versioned cross-block state (§6, §15) — relocated to
//! [`detector_api::cross_block_state`] (Sprint 16) so a non-`detection` writer
//! (the predictive pipeline's position tracker, §16.1) can reuse the same
//! snapshot/rewind primitive without depending on this service crate, which
//! arch-conformance forbids for anything but `backtest`. Re-exported here so
//! `detection::state::CrossBlockState` / `crate::state::CrossBlockState` keep
//! resolving unchanged for this crate's own `Scope::CrossBlock` roster
//! (`reorg::CrossBlockStates`).

pub use detector_api::CrossBlockState;
