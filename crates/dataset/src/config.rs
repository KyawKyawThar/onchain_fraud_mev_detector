//! Configuration, resolved once from the environment at startup.
//!
//! The single place this binary reads env (the event-store discipline, via the
//! shared [`telemetry::env`] helpers): everything downstream takes an explicit
//! value, so the pipeline stays pure and testable.
//!
//! Only *connection* details live here. Everything that decides which rows come
//! out is a CLI flag folded into [`crate::DatasetSpec`] — an environment
//! variable that silently changed a dataset's contents would defeat the whole
//! reproducibility story.

use anyhow::Result;
use secrecy::SecretString;
use telemetry::env::parse_or;

/// Where the event store serves its replay API.
pub const EVENT_STORE_URL_ENV: &str = "EVENT_STORE_URL";
const DEFAULT_EVENT_STORE_URL: &str = "http://127.0.0.1:8081";

/// How to reach ClickHouse. Shares the physical instance (and the
/// `CLICKHOUSE_*` env) with the other analytical stores in the dev stack, but
/// owns its tables and migration bookkeeping outright (§14: no shared tables).
#[derive(Debug, Clone)]
pub struct ClickhouseConfig {
    /// HTTP-interface base URL, e.g. `http://127.0.0.1:8123` (no creds, no db).
    pub url: String,
    pub user: String,
    pub password: SecretString,
    pub database: String,
}

impl ClickhouseConfig {
    /// Read from `CLICKHOUSE_URL` / `_USER` / `_PASSWORD` / `_DATABASE`, the
    /// same names every other ClickHouse consumer in the workspace uses.
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            url: parse_or("CLICKHOUSE_URL", "http://127.0.0.1:8123".to_owned())?,
            user: parse_or("CLICKHOUSE_USER", "default".to_owned())?,
            password: SecretString::from(parse_or("CLICKHOUSE_PASSWORD", String::new())?),
            database: parse_or("CLICKHOUSE_DATABASE", "mev".to_owned())?,
        })
    }
}

/// Everything the binary needs to reach its two dependencies.
#[derive(Debug, Clone)]
pub struct Config {
    /// Event-store service root, e.g. `http://event-store:8081`. The `/v1/replay`
    /// path is appended by the source.
    pub event_store_url: String,
    pub clickhouse: ClickhouseConfig,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            event_store_url: parse_or(EVENT_STORE_URL_ENV, DEFAULT_EVENT_STORE_URL.to_owned())?,
            clickhouse: ClickhouseConfig::from_env()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn defaults_point_at_the_local_dev_stack() {
        // No env set in a fresh process: the defaults are the compose stack's
        // addresses, so `just` recipes work with no exports.
        let cfg = Config::from_env().expect("defaults resolve");
        assert!(cfg.event_store_url.starts_with("http://"));
        assert!(cfg.clickhouse.url.starts_with("http://"));
        assert!(!cfg.clickhouse.database.is_empty());
    }

    #[test]
    fn the_password_stays_out_of_debug_output() {
        let cfg = ClickhouseConfig {
            url: "http://ch:8123".into(),
            user: "default".into(),
            password: SecretString::from("hunter2".to_owned()),
            database: "mev".into(),
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert_eq!(cfg.password.expose_secret(), "hunter2");
    }
}
