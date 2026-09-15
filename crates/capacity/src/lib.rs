//! **What the platform's ClickHouse and Kafka will cost, before it costs it**
//! (readiness Epic D).
//!
//! The event store never deletes except by retention (§4, conventions §18), so
//! its size is a function of three things this workspace already commits: how
//! many events of each type a day produces, how big each one is, and how long
//! the evidence window holds them. This crate multiplies them out over a growth
//! horizon into what an operator buys — shards, disks, broker storage, a bill —
//! and into the limits that are not bought but *hit*.
//!
//! ```text
//!   model.json ────────┐                     workload ─► timeline ─┐
//!   events corpus ─────┤                                            ├─► plan ─► checks ─► report
//!   every crate's DDL ─┼─► inputs ─► tables (replayed partition keys)┤
//!   retention policy ──┘                     kafka ─────────────────┘
//! ```
//!
//! A pipeline of pure stages with typed outputs ([`workload`] → [`timeline`] →
//! [`plan`]), judged by a registry of independent [`checks`]. No stage does
//! I/O except reading committed files at the edge, so the whole gate runs in a
//! plain `cargo test`.
//!
//! # Why the limits matter more than the bill
//!
//! A bill grows smoothly and is noticed. A ClickHouse server limit is a cliff:
//! the first model run found the event store's original daily partition key
//! would pass `max_parts_in_total` on day 1258 of a 2192-day window and refuse
//! every insert, and that one per-record insert per event would pass the parts
//! economics long before that. Nothing on the live path could have seen either,
//! because a young table is exactly the workload that never trips them.
//!
//! # Every input carries its provenance
//!
//! Rates are projections, each with a rationale. Payload sizes are measured
//! from the schema corpus. Partition keys are replayed from the migrations.
//! Parameters that are none of those are [`model::Estimate`]s, tagged assumed
//! or measured, and every report lists the ones still assumed.

pub mod checks;
pub mod corpus;
pub mod ddl;
pub mod kafka;
pub mod key;
pub mod model;
pub mod plan;
pub mod report;
pub mod timeline;
pub mod units;
pub mod workload;

use std::path::PathBuf;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The committed capacity profile.
pub fn committed_model_path() -> PathBuf {
    crate_dir().join("model.json")
}

/// The event schema corpus: one real envelope per shape ever emitted.
pub fn default_corpus_dir() -> PathBuf {
    crate_dir().join("../events/schema/corpus")
}

/// Every crate — the ClickHouse tables are replayed from each one's
/// `migrations/` directory.
pub fn default_crates_dir() -> PathBuf {
    crate_dir().join("..")
}

/// The deployment tree the model's `deployed_*` fields are pinned to.
pub fn deploy_dir() -> PathBuf {
    crate_dir().join("../../deploy")
}
