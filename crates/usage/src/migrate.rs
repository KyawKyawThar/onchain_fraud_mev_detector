//! ClickHouse schema migrations for the usage service (§13, §14).
//!
//! The runner logic lives in the shared [`ch_migrate`] crate; this module owns
//! only what is service-specific: the migration set and the
//! **`usage_schema_migrations`** bookkeeping table — separate from
//! event-store's, simulation's and intelligence's, because the services
//! version their ClickHouse tables independently (§14) even when they share a
//! physical instance in dev.
//!
//! Add a migration by dropping a numbered `*.up.sql`/`*.down.sql` pair in
//! `migrations/` (one statement per file, **no literal `?` anywhere** — the
//! runner validates both) and appending one entry to [`MIGRATIONS`].

use ch_migrate::{Migration, Migrator};

/// The ordered migration set. Versions sort lexically, so zero-pad the numeric
/// prefix.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: "0001_create_usage_events",
        up: include_str!("../migrations/0001_create_usage_events.up.sql"),
        down: include_str!("../migrations/0001_create_usage_events.down.sql"),
    },
    Migration {
        version: "0002_create_usage_rollup_daily",
        up: include_str!("../migrations/0002_create_usage_rollup_daily.up.sql"),
        down: include_str!("../migrations/0002_create_usage_rollup_daily.down.sql"),
    },
    Migration {
        version: "0003_create_usage_rollup_mv",
        up: include_str!("../migrations/0003_create_usage_rollup_mv.up.sql"),
        down: include_str!("../migrations/0003_create_usage_rollup_mv.down.sql"),
    },
];

/// The usage service's migrator: applied on service boot via
/// [`run`](Migrator::run), or driven explicitly through the
/// `usage migrate up|down|info` subcommand ([`cli`](Migrator::cli)).
pub const MIGRATOR: Migrator = Migrator::new("usage", "usage_schema_migrations", MIGRATIONS);
