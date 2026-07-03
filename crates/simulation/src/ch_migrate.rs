//! ClickHouse schema migrations for the incident-analytics projection (§7, §14).
//!
//! The runner logic lives in the shared [`ch_migrate`](ch_migrate_lib) crate;
//! this module owns only what is service-specific: the migration set and the
//! **`sim_schema_migrations`** bookkeeping table — separate from the event
//! store's and intelligence's, because the services version their ClickHouse
//! tables independently (§14) even when they share a physical instance in dev.
//!
//! Add a migration by dropping a numbered `*.up.sql`/`*.down.sql` pair in
//! `migrations/` (one statement per file, **no literal `?` anywhere** — the
//! runner validates both) and appending one entry to [`MIGRATIONS`].

use ch_migrate::{Migration, Migrator};

/// The ordered migration set. Versions sort lexically, so zero-pad the numeric
/// prefix.
const MIGRATIONS: &[Migration] = &[Migration {
    version: "0001_create_incident_analytics",
    up: include_str!("../migrations/0001_create_incident_analytics.up.sql"),
    down: include_str!("../migrations/0001_create_incident_analytics.down.sql"),
}];

/// The simulation service's migrator: applied on the projection consumer's
/// boot via [`run`](Migrator::run), or driven explicitly through the
/// `simulation-projection migrate up|down|info` subcommand
/// ([`cli`](Migrator::cli)).
pub const MIGRATOR: Migrator =
    Migrator::new("simulation analytics", "sim_schema_migrations", MIGRATIONS);
