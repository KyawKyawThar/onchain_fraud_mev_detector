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
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: "0001_create_incident_analytics",
        up: include_str!("../migrations/0001_create_incident_analytics.up.sql"),
        down: include_str!("../migrations/0001_create_incident_analytics.down.sql"),
    },
    Migration {
        version: "0002_victim_address_business_key",
        up: include_str!("../migrations/0002_victim_address_business_key.up.sql"),
        down: include_str!("../migrations/0002_victim_address_business_key.down.sql"),
    },
    Migration {
        version: "0003_create_incident_timing_rollup",
        up: include_str!("../migrations/0003_create_incident_timing_rollup.up.sql"),
        down: include_str!("../migrations/0003_create_incident_timing_rollup.down.sql"),
    },
    Migration {
        version: "0004_create_incident_timing_rollup_mv",
        up: include_str!("../migrations/0004_create_incident_timing_rollup_mv.up.sql"),
        down: include_str!("../migrations/0004_create_incident_timing_rollup_mv.down.sql"),
    },
];

/// The simulation service's migrator: applied on the projection consumer's
/// boot via [`run`](Migrator::run), or driven explicitly through the
/// `simulation-projection migrate up|down|info` subcommand
/// ([`cli`](Migrator::cli)).
pub const MIGRATOR: Migrator =
    Migrator::new("simulation analytics", "sim_schema_migrations", MIGRATIONS);

#[cfg(test)]
mod tests {
    use super::MIGRATOR;

    /// The migration set is a compile-time constant, so its well-formedness is
    /// a compile-time property — but `Migrator::run` only checks it against a
    /// live ClickHouse, which in practice means a service boot or a `#[ignore]`d
    /// integration test. Neither runs on an ordinary `cargo test`, so a
    /// malformed file sits green in every fast gate and takes down simulation the
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
