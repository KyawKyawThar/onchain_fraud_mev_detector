//! Intelligence service binary (§8) — Sprint 7 t1: the data-store milestone.
//!
//! The event consumer (attribution on `IncidentCreated`, t4) is not built yet,
//! so this binary currently ships the two *operational* entry points the
//! stores need — the same split as `simulation-projection`:
//!
//!   - `migrate up|down|info` — drive the ClickHouse adjacency migrations
//!     (Postgres migrations are applied out-of-band by sqlx-cli via
//!     `just migrate-*`, the workspace-wide convention).
//!   - `ping` — connect and probe all three stores (Postgres schema, Redis,
//!     ClickHouse), so a misconfigured deployment fails fast and visibly.

use anyhow::{bail, Context, Result};
use clickhouse::Client;
use intelligence::adjacency::{build_clickhouse_client, ClickhouseAdjacency};
use intelligence::cache::RedisHotCache;
use intelligence::ch_migrate;
use intelligence::config::Config;
use intelligence::store::PgIntelligenceStore;
use secrecy::ExposeSecret;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("intelligence"))?;
    let cfg = Config::from_env()?;
    let client = build_clickhouse_client(&cfg.clickhouse);

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("migrate") => {
            ch_migrate::MIGRATOR
                .cli(&client, args.next().as_deref())
                .await
        }
        Some("ping") => ping(&cfg, client).await,
        Some(other) => bail!(
            "unknown argument {other:?}; expected `migrate up|down|info` or `ping` \
             (the intelligence event consumer lands with Sprint 7 t4)"
        ),
        None => bail!(
            "the intelligence event consumer lands with Sprint 7 t4; \
             use `migrate up|down|info` or `ping`"
        ),
    }
}

/// Prove all three stores are reachable and schema'd — the boot-time fail-fast
/// probe, runnable on its own for deploy smoke checks.
async fn ping(cfg: &Config, client: Client) -> Result<()> {
    ch_migrate::MIGRATOR
        .run(&client)
        .await
        .context("running ClickHouse adjacency migrations")?;

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    PgIntelligenceStore::new(pool)
        .ping()
        .await
        .context("probing the Postgres intelligence schema (run `just migrate-up`?)")?;
    println!("✅ postgres: reachable, intelligence schema applied");

    RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
        .await
        .context("connecting to Redis")?;
    println!("✅ redis: reachable");

    ClickhouseAdjacency::new(client)
        .ping()
        .await
        .context("probing ClickHouse")?;
    println!("✅ clickhouse: reachable, adjacency schema applied");
    Ok(())
}
