//! ClickHouse schema migrations for the intelligence service's analytical
//! tables (§8.2, §10, §14, §20.3): the address-adjacency graph, the
//! block-production records, and the per-address behavior embeddings.
//!
//! The runner logic lives in the shared [`ch_migrate`](ch_migrate_lib) crate;
//! this module owns only what is service-specific: the migration set and the
//! **`intel_schema_migrations`** bookkeeping table — separate from the event
//! store's and simulation's, because the services version their ClickHouse
//! tables independently (§14) even when they share a physical instance in dev.
//!
//! Add a migration by dropping a numbered `*.up.sql`/`*.down.sql` pair in
//! `migrations/` (one statement per file, **no literal `?` anywhere** — the
//! runner validates both) and appending one entry to [`MIGRATIONS`].

use ch_migrate::{Migration, Migrator};

/// The ordered migration set. Versions sort lexically, so zero-pad the numeric
/// prefix.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: "0001_create_address_adjacency",
        up: include_str!("../migrations/0001_create_address_adjacency.up.sql"),
        down: include_str!("../migrations/0001_create_address_adjacency.down.sql"),
    },
    Migration {
        version: "0002_create_block_production",
        up: include_str!("../migrations/0002_create_block_production.up.sql"),
        down: include_str!("../migrations/0002_create_block_production.down.sql"),
    },
    Migration {
        version: "0003_add_cross_chain_columns",
        up: include_str!("../migrations/0003_add_cross_chain_columns.up.sql"),
        down: include_str!("../migrations/0003_add_cross_chain_columns.down.sql"),
    },
    Migration {
        version: "0004_create_address_embeddings",
        up: include_str!("../migrations/0004_create_address_embeddings.up.sql"),
        down: include_str!("../migrations/0004_create_address_embeddings.down.sql"),
    },
    Migration {
        version: "0005_index_adjacency_observed_at",
        up: include_str!("../migrations/0005_index_adjacency_observed_at.up.sql"),
        down: include_str!("../migrations/0005_index_adjacency_observed_at.down.sql"),
    },
    Migration {
        version: "0006_create_behavior_baselines",
        up: include_str!("../migrations/0006_create_behavior_baselines.up.sql"),
        down: include_str!("../migrations/0006_create_behavior_baselines.down.sql"),
    },
    Migration {
        version: "0007_index_address_embeddings_vector",
        up: include_str!("../migrations/0007_index_address_embeddings_vector.up.sql"),
        down: include_str!("../migrations/0007_index_address_embeddings_vector.down.sql"),
    },
    Migration {
        version: "0008_create_address_neighbors",
        up: include_str!("../migrations/0008_create_address_neighbors.up.sql"),
        down: include_str!("../migrations/0008_create_address_neighbors.down.sql"),
    },
];

/// The intelligence service's migrator: apply on boot via
/// [`run`](Migrator::run), or drive explicitly through the binary's
/// `migrate up|down|info` subcommand ([`cli`](Migrator::cli)).
pub const MIGRATOR: Migrator = Migrator::new("intelligence", "intel_schema_migrations", MIGRATIONS);
