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
//! What deliberately does *not* live here: petgraph subgraph analysis is
//! bounded and in-memory (load a capped neighborhood, analyze, discard — §8);
//! the Kafka consumer (attribution on `IncidentCreated`, t4), label seeding
//! (t2), clustering (t3) and the per-entity merge actor (t5) land on top of
//! these seams. The fast path stays attribution-blind (§6/§8): nothing in
//! detection reads these stores.

pub mod adjacency;
pub mod cache;
pub mod ch_migrate;
pub mod config;
pub mod model;
pub mod store;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
