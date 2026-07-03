//! ClickHouse schema migrations for the event store (§4).
//!
//! The runner logic lives in the shared [`ch_migrate`] crate; this module owns
//! only what is service-specific: the migration set and the
//! **`schema_migrations`** bookkeeping table — separate from simulation's and
//! intelligence's, because the services version their ClickHouse tables
//! independently (§14) even when they share a physical instance in dev.
//!
//! Add a migration by dropping a numbered `*.up.sql`/`*.down.sql` pair in
//! `migrations/` (one statement per file, **no literal `?` anywhere** — the
//! runner validates both) and appending one entry to [`MIGRATIONS`].

use ch_migrate::{Migration, Migrator};

/// The ordered migration set. Versions sort lexically, so zero-pad the numeric
/// prefix.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: "0001_create_events",
        up: include_str!("../migrations/0001_create_events.up.sql"),
        down: include_str!("../migrations/0001_create_events.down.sql"),
    },
    Migration {
        version: "0002_business_key_columns",
        up: include_str!("../migrations/0002_business_key_columns.up.sql"),
        down: include_str!("../migrations/0002_business_key_columns.down.sql"),
    },
];

/// The event store's migrator: applied on service boot via
/// [`run`](Migrator::run), or driven explicitly through the
/// `event-store migrate up|down|info` subcommand ([`cli`](Migrator::cli)).
pub const MIGRATOR: Migrator = Migrator::new("event store", "schema_migrations", MIGRATIONS);
