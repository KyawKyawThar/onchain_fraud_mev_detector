//! Intelligence service binary (§8) — Sprint 7 t1/t2: data stores + seeding.
//!
//! The event consumer (attribution on `IncidentCreated`, t4) is not built yet,
//! so this binary currently ships the *operational* entry points the stores
//! need — the same split as `simulation-projection`:
//!
//!   - `migrate up|down|info` — drive the ClickHouse adjacency migrations
//!     (Postgres migrations are applied out-of-band by sqlx-cli via
//!     `just migrate-*`, the workspace-wide convention).
//!   - `ping` — connect and probe all three stores (Postgres schema, Redis,
//!     ClickHouse), so a misconfigured deployment fails fast and visibly.
//!   - `seed <feed> <file> [source-detail]` — import a downloaded §8.1 public
//!     feed (t2). Downloading stays out-of-band (see the justfile), so the
//!     import is a reproducible file, not a moving URL.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clickhouse::Client;
use events::primitives::Chain;
use intelligence::adjacency::{build_clickhouse_client, ClickhouseAdjacency};
use intelligence::cache::RedisHotCache;
use intelligence::ch_migrate;
use intelligence::cluster::{cluster_address, ClusterLimits};
use intelligence::config::Config;
use intelligence::seed::{Feed, Seeder};
use intelligence::store::PgIntelligenceStore;
use secrecy::ExposeSecret;
use tracing::Instrument;

const USAGE: &str = "expected `migrate up|down|info`, `ping`, \
                     `seed <etherscan-tags|ofac-sdn|mev-list|protocol-registry> <file> [source-detail]`, or \
                     `cluster <chain-id> <address>` \
                     (the intelligence event consumer lands with Sprint 7 t4)";

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
        Some("seed") => seed(&cfg, args).await,
        Some("cluster") => cluster(&cfg, client, args).await,
        Some(other) => bail!("unknown argument {other:?}; {USAGE}"),
        None => bail!("{USAGE}"),
    }
}

/// Import one downloaded §8.1 feed file: parse (pure, hard error with a
/// location on any malformed row), then apply through the Postgres store and
/// evict touched addresses from the hot cache. Re-running the same file is an
/// idempotent no-op (deterministic seeded label ids + keyed sanctions upsert).
async fn seed(cfg: &Config, mut args: impl Iterator<Item = String>) -> Result<()> {
    let feed: Feed = match args.next() {
        Some(raw) => raw
            .parse()
            .map_err(|_| anyhow::anyhow!("unknown feed {raw:?}; {USAGE}"))?,
        None => bail!("missing feed; {USAGE}"),
    };
    let Some(path) = args.next() else {
        bail!("missing feed file path; {USAGE}");
    };
    // Optional provenance override naming the specific list/registry; an empty
    // arg (justfile default) means "use the feed's canonical name".
    let detail = args
        .next()
        .filter(|raw| !raw.is_empty())
        .unwrap_or_else(|| feed.canonical_detail().to_owned());

    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading feed file {path:?}"))?;
    let batch = feed.parse(&raw, &detail, chrono::Utc::now())?;
    println!(
        "parsed {path}: {} labels, {} sanctions rows (source_detail {detail:?})",
        batch.labels.len(),
        batch.sanctions.len()
    );

    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = Arc::new(PgIntelligenceStore::new(pool));
    let cache = RedisHotCache::connect(cfg.redis.url.expose_secret(), cfg.redis.cache_ttl)
        .await
        .context("connecting to Redis")?;

    // The span names *which* feed/file this import is; `Seeder::apply`'s own
    // instrumentation nests the batch sizes and outcome under it.
    let report = Seeder::new(store.clone(), store, Arc::new(cache))
        .apply(&batch)
        .instrument(tracing::info_span!("seed_import", %feed, %detail, path = %path))
        .await
        .context("applying the parsed feed (safe to re-run: writes are keyed)")?;
    println!("✅ {report}");
    Ok(())
}

/// Run one basic-entity-clustering pass (§8.2, Sprint 7 t3) from a seed
/// address: walk the adjacency graph over the funder/deployer/
/// profit-receiver/code-hash signal only, degree-capped and hop-bounded, then
/// apply the resulting component to the Postgres entity store. Safe to re-run
/// (idempotent) and safe to seed on an unknown or infrastructure address (the
/// latter simply reports no cluster).
async fn cluster(
    cfg: &Config,
    client: Client,
    mut args: impl Iterator<Item = String>,
) -> Result<()> {
    let Some(chain_id) = args.next() else {
        bail!("missing chain id; {USAGE}");
    };
    let chain = Chain(
        chain_id
            .parse()
            .map_err(|_| anyhow::anyhow!("chain id {chain_id:?} is not a u64; {USAGE}"))?,
    );
    let Some(raw_address) = args.next() else {
        bail!("missing address; {USAGE}");
    };
    let address = raw_address
        .parse()
        .map_err(|_| anyhow::anyhow!("address {raw_address:?} is not 0x-hex; {USAGE}"))?;

    let graph = ClickhouseAdjacency::new(client);
    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let store = PgIntelligenceStore::new(pool);

    let outcome = cluster_address(
        &graph,
        &store,
        chain,
        &address,
        "cli:cluster",
        chrono::Utc::now(),
        ClusterLimits::default(),
    )
    .instrument(tracing::info_span!("cluster_address", %chain, %raw_address))
    .await
    .context("clustering the seed address")?;

    match outcome {
        Some(outcome) => println!(
            "✅ entity {}: {} newly linked, {} entities absorbed, {} hubs excluded ({:?})",
            outcome.entity_id,
            outcome.linked.len(),
            outcome.absorbed.len(),
            outcome.hubs.len(),
            outcome.hubs,
        ),
        None => println!(
            "no cluster formed: {raw_address} is itself an infrastructure endpoint \
             (degree over the cap at hop 0)"
        ),
    }
    Ok(())
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
