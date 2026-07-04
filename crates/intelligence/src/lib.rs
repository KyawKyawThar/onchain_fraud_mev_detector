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
//! What deliberately does *not* live here yet: the Kafka consumer
//! (attribution on `IncidentCreated`, t4) and the per-entity merge actor (t5)
//! land on top of these seams. The fast path stays attribution-blind
//! (§6/§8): nothing in detection reads these stores.

pub mod adjacency;
pub mod cache;
pub mod ch_migrate;
pub mod cluster;
pub mod config;
pub mod model;
pub mod seed;
pub mod store;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
