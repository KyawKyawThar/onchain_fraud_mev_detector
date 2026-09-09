//! ClickHouse schema migrations for the dataset exporter (§14, §20.1).
//!
//! The runner logic lives in the shared [`ch_migrate`] crate; this module owns
//! only what is specific to this binary: the migration set and the
//! **`dataset_schema_migrations`** bookkeeping table — separate from
//! event-store's, simulation's, intelligence's and usage's, because each owns
//! its ClickHouse tables independently (§14) even when they share a physical
//! instance in dev.
//!
//! Add a migration by dropping a numbered `*.up.sql`/`*.down.sql` pair in
//! `migrations/` (one statement per file, **no literal `?` anywhere** — the
//! runner validates both) and appending one entry to [`MIGRATIONS`].

use ch_migrate::{Migration, Migrator};

/// The ordered migration set. Versions sort lexically, so zero-pad the numeric
/// prefix.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: "0001_create_ml_dataset_rows",
        up: include_str!("../migrations/0001_create_ml_dataset_rows.up.sql"),
        down: include_str!("../migrations/0001_create_ml_dataset_rows.down.sql"),
    },
    Migration {
        version: "0002_create_ml_dataset_manifests",
        up: include_str!("../migrations/0002_create_ml_dataset_manifests.up.sql"),
        down: include_str!("../migrations/0002_create_ml_dataset_manifests.down.sql"),
    },
];

/// This binary's migrator: applied before an export that targets ClickHouse, or
/// driven explicitly through the `dataset migrate up|down|info` subcommand.
pub const MIGRATOR: Migrator = Migrator::new("dataset", "dataset_schema_migrations", MIGRATIONS);

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared runner re-checks all of this at boot, but its `validate` is
    /// private and only runs when a ClickHouse is reachable — so the same rules
    /// are asserted here, where a violation fails `cargo test` instead of a
    /// deploy. (The `?` rule is the one that bites: the clickhouse client
    /// parses every literal question mark as a bind placeholder, *including
    /// ones inside SQL comments*, and the resulting "unbound query argument"
    /// names nothing useful.)
    #[test]
    fn no_migration_file_contains_a_literal_question_mark() {
        for migration in MIGRATIONS {
            for (sql, direction) in [(migration.up, "up"), (migration.down, "down")] {
                assert!(
                    !sql.contains('?'),
                    "{}.{direction}.sql contains a literal '?' — reword it",
                    migration.version
                );
            }
        }
    }

    #[test]
    fn versions_are_strictly_ascending_because_list_order_is_apply_order() {
        for pair in MIGRATIONS.windows(2) {
            assert!(
                pair[0].version < pair[1].version,
                "{:?} is listed before {:?}",
                pair[0].version,
                pair[1].version
            );
        }
    }

    #[test]
    fn each_file_is_a_single_statement() {
        // The runner executes a whole file as one query, so a stray `;` in the
        // middle would silently drop everything after it.
        for migration in MIGRATIONS {
            for (sql, direction) in [(migration.up, "up"), (migration.down, "down")] {
                let statements = sql
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("--"))
                    .filter(|line| line.contains(';'))
                    .count();
                assert_eq!(
                    statements, 1,
                    "{}.{direction}.sql must be exactly one statement",
                    migration.version
                );
            }
        }
    }

    /// The migration set is a compile-time constant, so its well-formedness is
    /// a compile-time property — but `Migrator::run` only checks it against a
    /// live ClickHouse, which in practice means a service boot or a `#[ignore]`d
    /// integration test. Neither runs on an ordinary `cargo test`, so a
    /// malformed file sits green in every fast gate and takes down dataset the
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
