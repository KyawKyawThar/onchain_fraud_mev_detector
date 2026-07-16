//! ClickHouse schema migrations for the intelligence service's analytical
//! tables (§8.2, §10, §14): the address-adjacency graph and the
//! block-production records.
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
];

/// The intelligence service's migrator: apply on boot via
/// [`run`](Migrator::run), or drive explicitly through the binary's
/// `migrate up|down|info` subcommand ([`cli`](Migrator::cli)).
pub const MIGRATOR: Migrator = Migrator::new("intelligence", "intel_schema_migrations", MIGRATIONS);
