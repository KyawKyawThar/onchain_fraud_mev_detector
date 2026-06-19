//! ClickHouse schema migrations.
//!
//! ClickHouse has no first-class migration tool the way Postgres has sqlx, so
//! this is the small, dedicated analogue: a versioned `migrations/` directory of
//! `*.up.sql` / `*.down.sql` pairs, plus a runner that tracks applied versions
//! in a `schema_migrations` table. [`run`] (apply pending) executes on service
//! boot and is also reachable, with [`revert_last`] and [`status`], from the
//! `event-store migrate {up,down,info}` subcommand (see `main.rs`).
//!
//! Convention: **one statement per `.sql` file** — the runner executes each file
//! as a single ClickHouse query. Add a migration by dropping a numbered
//! up/down pair in `migrations/` and appending one entry to [`MIGRATIONS`].

use std::collections::HashSet;

use anyhow::{Context, Result};
use clickhouse::Client;

/// A single migration: an identifier plus its forward (`up`) and reverse
/// (`down`) SQL, embedded so they ship inside the Docker image.
struct Migration {
    version: &'static str,
    up: &'static str,
    down: &'static str,
}

/// The ordered migration set. Versions sort lexically, so zero-pad the numeric
/// prefix.
const MIGRATIONS: &[Migration] = &[Migration {
    version: "0001_create_events",
    up: include_str!("../migrations/0001_create_events.up.sql"),
    down: include_str!("../migrations/0001_create_events.down.sql"),
}];

/// Whether a migration has been applied — the result of [`status`].
pub struct MigrationStatus {
    pub version: &'static str,
    pub applied: bool,
}

/// Apply every migration not yet recorded in `schema_migrations`, in order.
/// Safe to call on every boot (idempotent). Returns the versions applied this
/// run.
pub async fn run(client: &Client) -> Result<Vec<&'static str>> {
    ensure_bookkeeping_table(client).await?;
    let done = applied_versions(client).await?;

    let mut applied = Vec::new();
    for migration in MIGRATIONS {
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
            .query("INSERT INTO schema_migrations (version) VALUES (?)")
            .bind(migration.version)
            .execute()
            .await
            .with_context(|| format!("recording migration {}", migration.version))?;

        tracing::info!(version = migration.version, "applied ClickHouse migration");
        applied.push(migration.version);
    }

    Ok(applied)
}

/// Revert the most recently applied migration: run its `down` SQL and drop its
/// `schema_migrations` row. Returns the version reverted, or `None` if nothing
/// was applied. Destructive — `0001`'s down drops the `events` table.
pub async fn revert_last(client: &Client) -> Result<Option<&'static str>> {
    ensure_bookkeeping_table(client).await?;
    let done = applied_versions(client).await?;

    // Walk newest→oldest and revert the first applied one.
    for migration in MIGRATIONS.iter().rev() {
        if !done.contains(migration.version) {
            continue;
        }

        client
            .query(migration.down)
            .execute()
            .await
            .with_context(|| format!("reverting migration {}", migration.version))?;

        client
            .query("DELETE FROM schema_migrations WHERE version = ?")
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
pub async fn status(client: &Client) -> Result<Vec<MigrationStatus>> {
    ensure_bookkeeping_table(client).await?;
    let done = applied_versions(client).await?;

    Ok(MIGRATIONS
        .iter()
        .map(|migration| MigrationStatus {
            version: migration.version,
            applied: done.contains(migration.version),
        })
        .collect())
}

/// Create the migration-tracking table itself. Bootstrapped inline (it predates
/// every migration), so it stays out of [`MIGRATIONS`].
async fn ensure_bookkeeping_table(client: &Client) -> Result<()> {
    client
        .query(
            "CREATE TABLE IF NOT EXISTS schema_migrations
             (
                 version    String,
                 applied_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
             )
             ENGINE = MergeTree
             ORDER BY version",
        )
        .execute()
        .await
        .context("creating schema_migrations table")
}

/// The set of already-applied migration versions, fetched in one query.
async fn applied_versions(client: &Client) -> Result<HashSet<String>> {
    let versions: Vec<String> = client
        .query("SELECT version FROM schema_migrations")
        .fetch_all()
        .await
        .context("listing applied migrations")?;
    Ok(versions.into_iter().collect())
}
