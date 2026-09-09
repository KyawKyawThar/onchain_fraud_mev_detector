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

#[cfg(test)]
mod tests {
    use super::MIGRATOR;

    /// The migration set is a compile-time constant, so its well-formedness is
    /// a compile-time property — but `Migrator::run` only checks it against a
    /// live ClickHouse, which in practice means a service boot or a `#[ignore]`d
    /// integration test. Neither runs on an ordinary `cargo test`, so a
    /// malformed file sits green in every fast gate and takes down usage the
    /// first time anything touches a real database.
    ///
    /// That is not hypothetical: a comment in `0003_events_retention.up.sql`
    /// that *warned about* the literal-bind-placeholder rule contained the
    /// character it warned about, and broke every ClickHouse-backed test in the
    /// workspace — discovered only in CI's Docker-gated job.
    #[test]
    fn the_migration_set_is_well_formed() {
        MIGRATOR
            .validate()
            .expect("migration set must be valid without a container");
    }
}
