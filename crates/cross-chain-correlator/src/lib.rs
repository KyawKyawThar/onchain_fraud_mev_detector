//! Cross-chain MEV correlator (§17, §24, Sprint 17 t1+t2) — bridge MEV and
//! cross-chain arbitrage only exist *across* chains, so this is the one
//! consumer in the workspace whose job is to hold every monitored chain's
//! event stream in one process rather than filtering foreign chains away.
//!
//! ```text
//! chain A stream ─┐   chain_consumer::ChainConsumer (one task per chain,
//! chain B stream ─┼─►  own consumer group, foreign-chain records committed
//! chain C stream ─┘   as no-ops) ──► router::LegRouter ──► one
//!                                     actor::CorrelationActor per
//!                                     configured bridge/pair, each folding
//!                                     an arriving leg through join::join_leg
//!                                     against its buffer::CandidateLegBuffer
//!                                     ──► BridgeMevDetected /
//!                                         CrossChainMevDetected
//! ```
//!
//! ## Scope
//!
//! **Task 1** wired the skeleton: the per-chain consumers, the
//! per-bridge/pair correlation actors, and the bounded, time-window-evicted
//! candidate-leg buffer — the cross-chain analogue of
//! [`detector_api::CrossBlockState`], windowed on wall-clock **observation
//! time** rather than block count (chains have different block times and
//! finality, §24), with the same memory-DoS discipline as
//! `simulation::cache`/`simulation::reorg::OrphanedBlocks`.
//!
//! **Task 2** ("windowed join on a behaviour-derived key") lands the rest:
//! [`join::join_leg`] matches a newly-arrived leg against its bridge/pair's
//! buffer on [`leg::CandidateLeg::correlation_key`] — a shared on-chain
//! funder/profit-receiver/bridge-recipient (§6, §24), attribution-blind by
//! construction — and, on a match, builds
//! [`events::cross_chain::BridgeMevDetected`] (a complementary
//! deposit/fill pair) or [`events::cross_chain::CrossChainMevDetected`] (two
//! or more same-kind legs closing a multi-chain cycle), each carrying every
//! matched leg's [`events::cross_chain::CrossChainLegRef`] (chain + block +
//! tx) so task 3's reorg handling has what it needs to retract a finding
//! whose least-final leg gets reverted. [`leg::EvidenceLegExtractor`]
//! replaces task 1's [`leg::StubExtractor`] as the real, generic (not
//! per-detector) [`leg::LegExtractor`] `main.rs` wires in — see its docs for
//! the evidence-field contract and why it is still a legitimate no-op
//! against today's live detectors.
//!
//! **Task 3** ("cross-chain finality + reorg") adds [`finality`]: a finding
//! is only as final as its least-final leg, so
//! [`finality::FindingFinalityTracker`] tracks every published finding's legs
//! until each is finalized (§15), and [`finality::FinalityConsumer`] retracts
//! the whole finding — publishing
//! [`events::cross_chain::CrossChainFindingRetracted`] — the instant *any*
//! leg's block reverts, via the same `finding_id` task 2 minted for exactly
//! this. [`finding_changelog`] gives that tracking durability (event-sourced,
//! replayed at boot), the same gap-closing move task 2's hardening pass made
//! for the leg buffer. See [`finality`]/[`finding_changelog`]'s module docs
//! for the full design.
//!
//! Task 4 wires findings into intelligence. See `sprint_plan.md`'s Sprint 17
//! row and `docs/onchain_mev_detector_v2_microservices_rev2.md` §17/§24.
//!
//! ## Production hardening (post-task-2)
//!
//! - **Horizontal sharding** — [`leg::BridgeOrPair::owned_by`] lets the
//!   bridge/pair roster be split across replicas, each still consuming every
//!   configured chain's full stream (a bridge/pair's two legs can arrive via
//!   any chain, so only sharding *by bridge/pair* — not by Kafka partition —
//!   guarantees both legs converge on one replica). See
//!   [`config::Config::owned_bridges_or_pairs`].
//! - **Durable buffer state** — [`changelog`] gives every buffer mutation a
//!   Kafka-backed log, replayed at boot ([`changelog::replay`]) so a
//!   restart reconstructs in-flight legs instead of silently losing them.
//! - **Non-blocking routing** — [`router::LegRouter::route`] no longer
//!   blocks a chain consumer on one stalled actor's channel; a full channel
//!   drops the leg (with a metric) instead of stalling every other
//!   bridge/pair sharing that chain's consumer.
//! - **Redelivery dedup** — [`chain_consumer::ChainConsumer`] tracks recently
//!   processed envelope ids so an at-least-once Kafka redelivery can't
//!   double-extract (and double-publish) the same leg.
//! - **Indexed buffer lookups + a Strategy-pattern join** —
//!   [`buffer::CandidateLegBuffer::candidates_for`] and [`join`]'s
//!   `MatchStrategy` chain, see their own module docs.

pub mod actor;
pub mod buffer;
pub mod chain_consumer;
pub mod changelog;
pub mod config;
pub mod finality;
pub mod finding_changelog;
pub mod join;
pub mod leg;
pub mod metrics;
pub mod router;
