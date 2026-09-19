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

use anyhow::{Context, Result};
use ch_migrate::swap::{SwapOutcome, TableSwap};
use ch_migrate::{Migration, Migrator};
use clickhouse::Client;

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
    // The capacity plan's replacement for incident_analytics (monthly key).
    // DDL only; `migrate` swaps it in when that moves no data.
    Migration {
        version: "0005_create_incident_analytics_next",
        up: include_str!("../migrations/0005_create_incident_analytics_next.up.sql"),
        down: include_str!("../migrations/0005_create_incident_analytics_next.down.sql"),
    },
    // The analyst-feedback ledger (§19, readiness Epic E) — the table the
    // false-positive SLI reads, joined against incident_analytics.
    Migration {
        version: "0006_create_incident_feedback",
        up: include_str!("../migrations/0006_create_incident_feedback.up.sql"),
        down: include_str!("../migrations/0006_create_incident_feedback.down.sql"),
    },
];

/// The simulation service's migrator, driven explicitly through the
/// `simulation-projection migrate up|down|info` subcommand
/// ([`cli`](Migrator::cli)). Every other path goes through [`migrate`], so the
/// table swap cannot be forgotten at one of them.
pub const MIGRATOR: Migrator =
    Migrator::new("simulation analytics", "sim_schema_migrations", MIGRATIONS);

/// The analytics table's capacity-plan replacement.
pub const ANALYTICS_SWAP: TableSwap = TableSwap::new("incident_analytics");

/// Apply the migrations, then complete the analytics table's replacement when
/// that moves no data.
///
/// The one schema entry point for the consumer's boot, the rebuild's live
/// connection and the rebuild's **staging database** — the last one matters
/// most: a staging database is always empty, so it always swaps, and a rebuild
/// therefore stages and promotes the monthly definition. That is how a live
/// table with data moves: `rebuild --model dashboards --yes`, not a copy.
pub async fn migrate(client: &Client) -> Result<SwapOutcome> {
    MIGRATOR
        .run(client)
        .await
        .context("running ClickHouse analytics migrations")?;
    let outcome = ANALYTICS_SWAP
        .swap_if_safe(client)
        .await
        .context("completing the incident_analytics replacement")?;
    match &outcome {
        SwapOutcome::Pending { live_rows, .. } => tracing::warn!(
            live_rows,
            "incident_analytics is still on its daily partition key and holds data; move it with \
             `simulation-projection rebuild --model dashboards --yes` (docs/runbooks/capacity-plan.md)"
        ),
        other => tracing::debug!(outcome = ?other, "incident_analytics definition is current"),
    }
    Ok(outcome)
}

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
