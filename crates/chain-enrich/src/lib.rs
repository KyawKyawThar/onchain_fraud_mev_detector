//! Archive-backed block enrichment (§5, §6; Hardening Epic E).
//!
//! The live ingestion source is header-only, so until this crate nothing in
//! the workspace could produce the context a detector is designed to read:
//! decoded transfers and swaps, pool reserves, token metadata and prices. This
//! crate builds exactly that from an archive node, for any historical block:
//!
//! - [`decode`], [`venue`], [`abi`] and [`config`] are pure. They decide what
//!   counts as an ERC-20 transfer, which `Swap` emitters are real pools
//!   (CREATE2-verified against configured venues, since anyone can emit the
//!   event), and which prices are fresh enough to use.
//! - [`probe`] checks a node and a config before a capture, with a
//!   pass / fail / inconclusive verdict.
//! - [`rpc::ArchiveRpc`] is the archive-read seam; [`alloy::AlloyArchiveRpc`] is
//!   its HTTP implementation with timeouts, jittered retry and failure
//!   classification (a pruned node is named as such).
//! - [`Enricher`] orchestrates one block: bounded concurrent reads, caches
//!   for immutable facts, and an [`EnrichReport`] of everything found absent.
//!
//! What it produces is `Fidelity::Enriched` in `dataset`'s terms: every
//! transaction, with its receipt, decoded under the rules above.
//!
//! Attribution-blind like the context it builds (§6): it reads what contracts
//! did, never who anyone is.

pub mod abi;
pub mod alloy;
pub mod config;
pub mod decode;
pub mod enricher;
pub mod probe;
pub mod rpc;
pub mod venue;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use alloy::AlloyArchiveRpc;
pub use config::{ConfigError, EnrichConfig, PriceFeed};
pub use enricher::{EnrichError, EnrichReport, EnrichedBlock, Enricher};
pub use probe::{probe, ProbeOptions, ProbeReport, Verdict};
pub use rpc::{ArchiveRpc, CallOutcome, RpcError, StateAt};
pub use venue::V2Venue;
