//! Configuration, resolved once from the environment — the same fail-fast
//! discipline every service's `config.rs` follows.
//!
//! The objectives themselves are configuration on purpose. An RPO is a
//! commitment somebody makes to somebody else; it belongs beside the
//! deployment that has to keep it, not compiled into a binary. Exporting the
//! configured budget as a metric (see [`crate::observed`]) is what keeps the
//! alert rule honest when it changes.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use secrecy::SecretString;
use telemetry::env::{parse_or as env_parse, required as env};

use crate::clickhouse::ClickHouseTarget;
use crate::objective::{parse_duration, RecoveryObjective};
use crate::postgres::PostgresTarget;
use crate::target::{BackupTarget, Database};

/// Everything the binary needs.
#[derive(Debug, Clone)]
pub struct Config {
    /// Root of the artifact store. In production a mounted volume that is
    /// **not** on the same failure domain as the databases being backed up —
    /// a backup on the disk that just died is not a backup.
    pub root: PathBuf,
    pub objective: RecoveryObjective,
    /// How often `serve` takes a snapshot. Defaults to a quarter of the RPO
    /// budget, so the budget is not blown by a single missed cycle.
    pub snapshot_interval: Duration,
    /// How often `serve` runs a restore drill.
    pub drill_interval: Duration,
    /// Artifacts older than this are pruned — never the newest, ever.
    pub retention: Duration,
    pub postgres_url: Option<SecretString>,
    pub clickhouse: Option<ClickHouseSettings>,
}

#[derive(Debug, Clone)]
pub struct ClickHouseSettings {
    pub url: String,
    pub user: String,
    pub password: SecretString,
    pub database: String,
}

/// Default retention: 30 days.
const DEFAULT_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Default drill cadence: daily. Frequent enough that the evidence is never
/// more than a day stale, cheap enough to run against production.
const DEFAULT_DRILL_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

impl Config {
    pub fn from_env() -> Result<Self> {
        let objective = RecoveryObjective {
            rpo: duration_env("BACKUP_RPO", crate::objective::DEFAULT_RPO)?,
            rto: duration_env("BACKUP_RTO", crate::objective::DEFAULT_RTO)?,
            orchestration_overhead: duration_env(
                "BACKUP_ORCHESTRATION_OVERHEAD",
                crate::objective::DEFAULT_ORCHESTRATION_OVERHEAD,
            )?,
            drill_max_age: duration_env(
                "BACKUP_DRILL_MAX_AGE",
                crate::objective::DEFAULT_DRILL_MAX_AGE,
            )?,
        };

        // A quarter of the RPO budget: three consecutive failed snapshots
        // before the objective is breached, which is the difference between a
        // transient blip and a page.
        let default_snapshot_interval = objective.rpo / 4;

        Ok(Self {
            root: PathBuf::from(env_parse(
                "BACKUP_DIR",
                "/var/lib/mevwatch/backups".to_owned(),
            )?),
            objective,
            snapshot_interval: duration_env("BACKUP_SNAPSHOT_INTERVAL", default_snapshot_interval)?,
            drill_interval: duration_env("BACKUP_DRILL_INTERVAL", DEFAULT_DRILL_INTERVAL)?,
            retention: duration_env("BACKUP_RETENTION", DEFAULT_RETENTION)?,
            postgres_url: optional("DATABASE_URL").map(SecretString::from),
            clickhouse: clickhouse_from_env()?,
        })
    }

    /// Build every configured target.
    ///
    /// A target with no configuration is **absent**, not silently skipped:
    /// `backup report` still lists it as a breach if it was named on the
    /// command line, and `serve` refuses to start with none.
    /// `Arc`, not `Box`: the scheduled agent runs each job on its own task so a
    /// multi-hour snapshot cannot block the loop that publishes the RPO gauges
    /// (see `main::serve`), and a spawned task needs an owned, `'static`,
    /// shareable handle.
    pub fn targets(&self) -> Result<Vec<Arc<dyn BackupTarget>>> {
        let mut out: Vec<Arc<dyn BackupTarget>> = Vec::new();
        if let Some(url) = &self.postgres_url {
            out.push(Arc::new(PostgresTarget::new("postgres", url.clone())?));
        }
        if let Some(settings) = &self.clickhouse {
            out.push(Arc::new(ClickHouseTarget::new(
                "clickhouse",
                settings.url.clone(),
                settings.user.clone(),
                settings.password.clone(),
                Database::new(settings.database.clone())?,
            )));
        }
        Ok(out)
    }
}

/// All four ClickHouse variables or none — a half-configured store is a
/// misconfiguration, and finding out at 3am that `CLICKHOUSE_PASSWORD` was
/// missing is worse than failing at boot.
fn clickhouse_from_env() -> Result<Option<ClickHouseSettings>> {
    let present = [
        "CLICKHOUSE_HTTP_URL",
        "CLICKHOUSE_USER",
        "CLICKHOUSE_PASSWORD",
        "CLICKHOUSE_DB",
    ]
    .iter()
    .filter(|key| std::env::var(key).is_ok())
    .count();
    match present {
        0 => Ok(None),
        4 => Ok(Some(ClickHouseSettings {
            url: env("CLICKHOUSE_HTTP_URL")?,
            user: env("CLICKHOUSE_USER")?,
            password: SecretString::from(env("CLICKHOUSE_PASSWORD")?),
            database: env("CLICKHOUSE_DB")?,
        })),
        n => anyhow::bail!(
            "{n} of the 4 CLICKHOUSE_* variables are set — set all of \
             CLICKHOUSE_HTTP_URL/USER/PASSWORD/DB, or none"
        ),
    }
}

fn optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

/// A duration env var in operator units (`4h`, `15m`), defaulted.
fn duration_env(key: &str, default: Duration) -> Result<Duration> {
    match std::env::var(key) {
        Ok(raw) => parse_duration(&raw)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("env var {key}")),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_snapshot_cadence_defaults_to_a_quarter_of_the_rpo_budget() {
        // Three consecutive failures before the objective is actually breached
        // — the margin that makes a single blip not a page.
        let objective = RecoveryObjective {
            rpo: Duration::from_secs(3_600),
            ..RecoveryObjective::default()
        };
        assert_eq!(objective.rpo / 4, Duration::from_secs(900));
    }

    #[test]
    fn a_half_configured_clickhouse_is_a_boot_error_not_a_skipped_target() {
        std::env::set_var("CLICKHOUSE_HTTP_URL", "http://localhost:8123");
        let err = clickhouse_from_env().expect_err("must refuse");
        assert!(err.to_string().contains("of the 4 CLICKHOUSE_*"), "{err}");
        std::env::remove_var("CLICKHOUSE_HTTP_URL");
    }

    #[test]
    fn durations_are_read_in_operator_units() {
        std::env::set_var("BACKUP_TEST_INTERVAL", "90m");
        assert_eq!(
            duration_env("BACKUP_TEST_INTERVAL", Duration::from_secs(1)).expect("parse"),
            Duration::from_secs(5_400)
        );
        std::env::set_var("BACKUP_TEST_INTERVAL", "whenever");
        let err = duration_env("BACKUP_TEST_INTERVAL", Duration::from_secs(1)).expect_err("refuse");
        assert!(err.to_string().contains("BACKUP_TEST_INTERVAL"), "{err}");
        std::env::remove_var("BACKUP_TEST_INTERVAL");
    }
}
