//! Shared ClickHouse schema-migration runner (§4, §14).
//!
//! ClickHouse has no first-class migration tool the way Postgres has sqlx, so
//! this crate is the small, dedicated analogue, extracted once event-store,
//! simulation and intelligence each carried a near-identical copy: a service
//! owns a versioned `migrations/` directory of `*.up.sql` / `*.down.sql` pairs
//! and constructs a [`Migrator`] over them with its **own** bookkeeping table
//! (`schema_migrations` / `sim_schema_migrations` / `intel_schema_migrations`)
//! — the services share one physical ClickHouse in the dev stack but version
//! their tables independently (§14: no shared tables).
//!
//! Conventions the runner enforces (fail-fast, before any DDL executes):
//! - **One statement per `.sql` file** — each file runs as a single query.
//! - **No literal `?` anywhere in a migration file, comments included** — the
//!   `clickhouse` client parses every `?` as a bind placeholder and fails with
//!   an opaque "unbound query argument"; [`Migrator`] rejects such a file with
//!   a message that names it instead.
//! - **Versions strictly ascending and unique** — the list order is the apply
//!   order, and versions sort lexically (zero-pad the numeric prefix), so a
//!   mis-ordered or copy-pasted entry is a bug caught at boot, not a schema
//!   applied out of order.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use clickhouse::Client;

/// A single migration: an identifier plus its forward (`up`) and reverse
/// (`down`) SQL, embedded via `include_str!` so they ship inside the image.
pub struct Migration {
    pub version: &'static str,
    pub up: &'static str,
    pub down: &'static str,
}

/// Whether a migration has been applied — the result of [`Migrator::status`].
pub struct MigrationStatus {
    pub version: &'static str,
    pub applied: bool,
}

/// A service's migration set bound to its own bookkeeping table. Construct one
/// `pub const MIGRATOR` per owning service; every entry point validates the
/// set before touching the database.
pub struct Migrator {
    /// Human name for CLI output, e.g. `"intelligence adjacency"`.
    display_name: &'static str,
    /// The service-private bookkeeping table, e.g. `"intel_schema_migrations"`.
    /// Interpolated into runner SQL — must be a compile-time constant, never
    /// runtime input.
    bookkeeping_table: &'static str,
    migrations: &'static [Migration],
}

impl Migrator {
    pub const fn new(
        display_name: &'static str,
        bookkeeping_table: &'static str,
        migrations: &'static [Migration],
    ) -> Self {
        Self {
            display_name,
            bookkeeping_table,
            migrations,
        }
    }

    /// Apply every migration not yet recorded, in order. Safe to call on every
    /// boot (idempotent). Returns the versions applied this run.
    pub async fn run(&self, client: &Client) -> Result<Vec<&'static str>> {
        self.validate()?;
        self.ensure_bookkeeping_table(client).await?;
        let done = self.applied_versions(client).await?;

        let mut applied = Vec::new();
        for migration in self.migrations {
            if done.contains(migration.version) {
                tracing::debug!(
                    version = migration.version,
                    "migration already applied, skipping"
                );
                continue;
            }

            client
                .query(migration.up)
                .execute()
                .await
                .with_context(|| format!("applying migration {}", migration.version))?;

            client
                .query(&format!(
                    "INSERT INTO {} (version) VALUES (?)",
                    self.bookkeeping_table
                ))
                .bind(migration.version)
                .execute()
                .await
                .with_context(|| format!("recording migration {}", migration.version))?;

            tracing::info!(version = migration.version, "applied ClickHouse migration");
            applied.push(migration.version);
        }

        Ok(applied)
    }

    /// Revert the most recently applied migration: run its `down` SQL and drop
    /// its bookkeeping row. Returns the version reverted, or `None` if nothing
    /// was applied. Destructive — a `down` typically drops a table.
    pub async fn revert_last(&self, client: &Client) -> Result<Option<&'static str>> {
        self.validate()?;
        self.ensure_bookkeeping_table(client).await?;
        let done = self.applied_versions(client).await?;

        // Walk newest→oldest and revert the first applied one.
        for migration in self.migrations.iter().rev() {
            if !done.contains(migration.version) {
                continue;
            }

            client
                .query(migration.down)
                .execute()
                .await
                .with_context(|| format!("reverting migration {}", migration.version))?;

            client
                .query(&format!(
                    "DELETE FROM {} WHERE version = ?",
                    self.bookkeeping_table
                ))
                .bind(migration.version)
                .execute()
                .await
                .with_context(|| format!("un-recording migration {}", migration.version))?;

            tracing::info!(version = migration.version, "reverted ClickHouse migration");
            return Ok(Some(migration.version));
        }

        Ok(None)
    }

    /// Report each known migration and whether it is applied, in order.
    pub async fn status(&self, client: &Client) -> Result<Vec<MigrationStatus>> {
        self.validate()?;
        self.ensure_bookkeeping_table(client).await?;
        let done = self.applied_versions(client).await?;

        Ok(self
            .migrations
            .iter()
            .map(|migration| MigrationStatus {
                version: migration.version,
                applied: done.contains(migration.version),
            })
            .collect())
    }

    /// The shared `migrate up|down|info` CLI arm every owning binary exposes
    /// (mirrors the sqlx/Postgres `just migrate-*` recipes). Prints to stdout
    /// — it is an operator tool, not a library path.
    pub async fn cli(&self, client: &Client, action: Option<&str>) -> Result<()> {
        match action {
            Some("up") => {
                let applied = self.run(client).await.context("migrate up")?;
                if applied.is_empty() {
                    println!("✅ migrate up: already up to date");
                } else {
                    println!("✅ migrate up: applied {}", applied.join(", "));
                }
            }
            Some("down") => match self.revert_last(client).await.context("migrate down")? {
                Some(version) => println!("⚠️  migrate down: reverted {version}"),
                None => println!("migrate down: nothing to revert"),
            },
            Some("info") => {
                let statuses = self.status(client).await.context("migrate info")?;
                println!("ClickHouse ({}) migrations:", self.display_name);
                for status in statuses {
                    let mark = if status.applied { "applied" } else { "pending" };
                    println!("  [{mark}] {}", status.version);
                }
            }
            other => bail!("unknown migrate action {other:?}; expected up, down, or info"),
        }
        Ok(())
    }

    /// Reject a malformed migration set before any DDL runs: a literal `?`
    /// anywhere in a file (the clickhouse client would bind it), or versions
    /// not strictly ascending (list order is apply order).
    fn validate(&self) -> Result<()> {
        for migration in self.migrations {
            for (sql, direction) in [(migration.up, "up"), (migration.down, "down")] {
                if sql.contains('?') {
                    bail!(
                        "migration {}.{direction}.sql contains a literal '?' (even in a \
                         comment): the clickhouse client parses every '?' as a bind \
                         placeholder — reword it",
                        migration.version
                    );
                }
            }
        }
        for pair in self.migrations.windows(2) {
            if pair[0].version >= pair[1].version {
                bail!(
                    "migration versions must be strictly ascending: {:?} is listed before {:?}",
                    pair[0].version,
                    pair[1].version
                );
            }
        }
        Ok(())
    }

    /// Create the migration-tracking table itself. Bootstrapped inline (it
    /// predates every migration), so it stays out of the migration list.
    async fn ensure_bookkeeping_table(&self, client: &Client) -> Result<()> {
        client
            .query(&format!(
                "CREATE TABLE IF NOT EXISTS {}
                 (
                     version    String,
                     applied_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
                 )
                 ENGINE = MergeTree
                 ORDER BY version",
                self.bookkeeping_table
            ))
            .execute()
            .await
            .with_context(|| format!("creating {} table", self.bookkeeping_table))
    }

    /// The set of already-applied migration versions, fetched in one query.
    async fn applied_versions(&self, client: &Client) -> Result<HashSet<String>> {
        let versions: Vec<String> = client
            .query(&format!("SELECT version FROM {}", self.bookkeeping_table))
            .fetch_all()
            .await
            .context("listing applied migrations")?;
        Ok(versions.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &[Migration] = &[
        Migration {
            version: "0001_a",
            up: "CREATE TABLE a (x UInt8) ENGINE = MergeTree ORDER BY x",
            down: "DROP TABLE a",
        },
        Migration {
            version: "0002_b",
            up: "CREATE TABLE b (x UInt8) ENGINE = MergeTree ORDER BY x",
            down: "DROP TABLE b",
        },
    ];

    #[test]
    fn a_wellformed_set_validates() {
        Migrator::new("test", "t_migrations", OK)
            .validate()
            .expect("valid set");
    }

    #[test]
    fn a_question_mark_is_rejected_even_in_a_comment() {
        const BAD: &[Migration] = &[Migration {
            version: "0001_a",
            up: "-- is this ok?\nCREATE TABLE a (x UInt8) ENGINE = MergeTree ORDER BY x",
            down: "DROP TABLE a",
        }];
        let err = Migrator::new("test", "t_migrations", BAD)
            .validate()
            .expect_err("must reject");
        assert!(err.to_string().contains("0001_a.up.sql"), "{err}");
    }

    #[test]
    fn out_of_order_or_duplicate_versions_are_rejected() {
        const SWAPPED: &[Migration] = &[
            Migration {
                version: "0002_b",
                up: "SELECT 1",
                down: "SELECT 1",
            },
            Migration {
                version: "0001_a",
                up: "SELECT 1",
                down: "SELECT 1",
            },
        ];
        assert!(Migrator::new("test", "t", SWAPPED).validate().is_err());

        const DUPED: &[Migration] = &[
            Migration {
                version: "0001_a",
                up: "SELECT 1",
                down: "SELECT 1",
            },
            Migration {
                version: "0001_a",
                up: "SELECT 1",
                down: "SELECT 1",
            },
        ];
        assert!(Migrator::new("test", "t", DUPED).validate().is_err());
    }
}
