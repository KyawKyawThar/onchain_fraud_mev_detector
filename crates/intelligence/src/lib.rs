//! Intelligence service (§8) — the moat: wallet labels, entity clustering,
//! attribution, risk scores and sanctions, consolidated behind one product
//! identity.
//!
//! Sprint 7 t1 builds the **data-store layer** (§14), three stores with three
//! jobs, each behind an object-safe seam with an in-memory double
//! ([`test_util`]):
//!
//! - [`store`] — **Postgres**, the mutable, transactional system of record:
//!   labels *with provenance* (conflicting labels coexist, never overwritten,
//!   §8.1), **versioned** entities + the address-membership invariant (§8.2),
//!   attribution records, sanctions lists (§8.5). Schema lives in
//!   `crates/db/migrations`, applied out-of-band by sqlx-cli.
//! - [`cache`] — **Redis**, the hot-path label/score cache: TTL-backed,
//!   **evicted on update**, an optimization never the record — serving the
//!   synchronous screening path (§11) and the predictive pipeline (§16).
//! - [`adjacency`] — **ClickHouse**, the append-only address graph, read as
//!   **degree-capped** neighborhoods (§8.2's critical hub-node rule, enforced
//!   in the seam). Schema owned by [`ch_migrate`], this service's own runner.
//!
//! Sprint 7 t2 adds [`seed`] on top: label seeding from the §8.1 public
//! sources (Etherscan tags, OFAC SDN, community MEV lists, protocol
//! registries) — pure per-feed parsers plus the [`seed::Seeder`] shell, with
//! deterministic seeded label ids so a re-import no-ops and a changed claim
//! coexists as a new row (conflicting labels stored, not overwritten).
//!
//! Sprint 7 t3 adds [`cluster`]: basic entity clustering over four adjacency
//! facts (funder/deployer/profit-receiver/code-hash), a bounded in-memory walk
//! from a seed address (load, analyze, discard — §8) that enforces the §8.2
//! hub-node degree cap by excluding any node whose cluster-relevant degree
//! exceeds the cap, then applies the resulting component to the entity store
//! idempotently.
//!
//! Sprint 7 t4 adds [`attribution`]: the Kafka consumer that attributes a
//! confirmed `IncidentCreated` to one or more entities, running the t2
//! (labels) and t3 (clustering) seams together and emitting every domain
//! event this pass discovers (`SanctionHit`, `EntityCreated`/`EntityMerged`,
//! `LabelAdded`, `AttributionUpdated`). The remaining three intelligence
//! events — `LabelUpdated`, `LabelRevoked`, `EntitySplit` — are *operator*
//! actions rather than incident-triggered ones: [`store::LabelStore::update_label_value`]/
//! [`revoke_label`](store::LabelStore::revoke_label) and
//! [`store::EntityStore::split`] are the store primitives, driven by the
//! `intelligence label-update|label-revoke|entity-split` CLI subcommands
//! (`main.rs`), which publish the corresponding event themselves (no consumer
//! of their own exists to do it).
//!
//! Sprint 7 t5 adds [`merge_actor`]: the per-entity merge actor that closes
//! the one gap left in t3/t4 — [`cluster::cluster_address`]'s owners-read →
//! plan → `create_entity`/`absorb`/`link_address` sequence is now held
//! together by a per-process [`merge_actor::MergeActorHandle`] lock (over
//! every entity id the pass has read as an owner) instead of racing other
//! in-process passes between those calls. Each individual store write was
//! already atomic and entity-locked at the Postgres layer (`store.rs`'s
//! `lock_entities`); the actor protects the *sequence*, not the primitive.
//! [`attribution::Attributor`] and the `intelligence cluster` CLI both share
//! one actor per process. The fast path stays attribution-blind (§6/§8):
//! nothing in detection reads these stores.
//!
//! Sprint 8 t1 adds [`risk`]: the pure risk-scoring kernel (§8.3) — labels,
//! attributions, sanctions and entity membership in, an explainable,
//! model-versioned, time-decayed [`events::intelligence::RiskScoreUpdated`]
//! out. It has no store dependency of its own; wiring it behind the
//! `(address, model_version)` cache with invalidate-on-input-change and
//! publishing the result (§8.3, t2) consumes it the same way `cluster`/
//! `attribution` consume their pure decision helpers.
//!
//! Sprint 8 t2 adds [`risk_scorer`]: the consumer that closes the loop —
//! every `LabelAdded`/`LabelUpdated`/`LabelRevoked`/`SanctionHit`/
//! `EntityCreated`/`EntityMerged`/`EntitySplit`/`AttributionUpdated` this
//! service (or an operator CLI command) emits is also this consumer's
//! trigger: it evicts the affected address(es)' hot-cache score entry,
//! recomputes via [`risk::score`] against current store state, repopulates
//! the `(address, model_version)` cache slot, and publishes the fresh
//! `RiskScoreUpdated` — the "scores invalidate and recompute automatically"
//! rule (§8.2/§8.3) made real.
//!
//! Sprint 8 t3 adds [`reorg`]: rolling back scores/merges on reorg (§15).
//! None of this crate's stores carry a block number, so it keys off
//! `IncidentRetracted` — the event a reorg already produces once
//! simulation's block→incident join withdraws an incident — rather than
//! `BlockReverted` directly. It withdraws the retracted incident's
//! `attributions` (publishing `AttributionRetracted`, a new event t2's
//! `risk_scorer` reacts to exactly like `AttributionUpdated`) and reverses
//! every merge that incident caused, via the merge log [`EntityStore::absorb`](store::EntityStore::absorb)
//! now writes and [`EntityStore::reverse_merge`](store::EntityStore::reverse_merge)
//! reads back — splitting the survivor apart again (publishing
//! `EntitySplit`, which `risk_scorer` also already consumes). A merge whose
//! survivor has moved on since is left logged, not silently undone.
//!
//! Sprint 8 t4 adds [`grpc`] and [`pb`] (generated from
//! `proto/intelligence.proto`): the crate's first gRPC surface, the
//! `IntelligenceRead` service the public API service (§11) calls for an
//! address's risk score and labels — cache-aside over the same
//! [`cache::HotCache`] and [`risk_scorer::load_risk_inputs`]/[`risk::score`]
//! seams the `score` consumer and `risk` CLI subcommand already use, so this
//! surface can't drift from how those already compute the same answer.
//!
//! Sprint 11 t1 adds the §10 block-production pipeline: [`production`] (the
//! `BlockProductionRecord` and its pure fold — the `tx → block` join that
//! attributes a confirmed incident to the block that carried it),
//! [`production_source`] (the chain full-block read and the MEV-Boost relay
//! data APIs, behind seams), [`production_store`] (append-only ClickHouse
//! snapshots, the read surface for the t2 builder leaderboard) and
//! [`production_consumer`] (the five-topic Kafka consumer tying them
//! together). Builder identity flows through `BuilderAddress` *labels* — read
//! from, and heuristically minted into, the same [`store::LabelStore`] the
//! rest of the service uses — never a hardcoded name table (§10).
//!
//! Sprint 17 t4 adds [`cross_chain_attribution`] and extracts [`association`]
//! (the §8.1/§8.6 flywheel pass, lifted out of [`attribution`] so both share
//! it): the cross-chain analogue of Sprint 7 t4 — `BridgeMevDetected`/
//! `CrossChainMevDetected` (§24) in, the same entity-clustering + association-
//! flywheel machinery run against each finding's `entity_hint` once per leg
//! chain, so a bridge deposit's chain-A funding cluster and its fill's
//! chain-B funding cluster converge on one entity. `entity_hint` itself is
//! never turned into a label — see [`cross_chain_attribution`]'s module docs.
//!
//! Sprint 19 t1 adds [`embedding`], [`embedding_store`] and [`embedding_job`]:
//! the §20.3 per-address **behavior vector** — activity cadence,
//! counterparty-type distribution, value-flow shape and incident history —
//! computed from the ClickHouse adjacency store, versioned exactly the way a
//! risk-score model is. The split is this crate's standard one:
//! [`embedding`] is the pure, frozen-schema kernel (no store dependency, like
//! [`risk`]), [`embedding_store`] is the append-only ClickHouse table
//! (latest-per-`(chain, address, version)`, like [`production_store`]), and
//! [`embedding_job`] is the shell — a `RiskScoreUpdated`-style invalidation
//! consumer *and* a scheduled sweep, because neither trigger alone is
//! sufficient: cadence drifts with time passing (which no event announces),
//! while a fresh sanctions hit must not wait out a sweep interval. Two
//! deliberate boundaries are documented at their modules: the embedding does
//! **not** fan out to a labeled address's neighbors (that is the one unbounded
//! path in the design, left to the sweep), and it reports no *monetary*
//! magnitude at all, because `address_adjacency` records relations rather than
//! amounts — encoded as an explicit "unknown", never imputed as zero.

pub mod adjacency;
pub mod association;
pub mod attribution;
pub mod cache;
pub mod ch_migrate;
pub mod cluster;
pub mod config;
pub mod cross_chain_attribution;
pub mod embedding;
pub mod embedding_consumer;
pub mod embedding_job;
pub mod embedding_store;
pub mod embedding_sweep;
pub mod graph;
pub mod grpc;
pub mod leaderboard;
pub mod merge_actor;
pub mod model;
pub mod pb;
pub mod production;
pub mod production_consumer;
pub mod production_source;
pub mod production_store;
pub mod reorg;
pub mod risk;
pub mod risk_scorer;
pub mod seed;
pub mod store;
pub mod timeline;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
