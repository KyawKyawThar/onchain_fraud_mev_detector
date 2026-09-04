//! Simulation incident/job **persistence** binary (§7, §14, Sprint 6 t5) — the
//! `simulation-projection` consumer.
//!
//! A separate binary from the dispatcher + worker because it is a Kafka projection, not a
//! revm worker: it consumes the result-path events, folds them through the pure
//! [`IncidentProjection`](simulation::projection), and write-throughs to Postgres (the
//! mutable in-flight-job + confirmed-incident read model) and ClickHouse (the append-only
//! incident-analytics firehose). It scales/deploys independently and holds no revm/RabbitMQ
//! dependency.
//!
//! Boot: stand up observability, resolve config, connect Postgres + ClickHouse and apply the
//! ClickHouse analytics migration (Postgres migrations are applied out-of-band by sqlx-cli /
//! `just migrate-*`), then drain the result topics until a shutdown signal.
//!
//! Run modes (first CLI arg):
//!   - *(none)* — run the consumer (the default).
//!   - `migrate up` / `migrate down` / `migrate info` — drive the ClickHouse analytics
//!     migrations explicitly and exit (the boot path always runs `up` too). Mirrors the
//!     event-store `migrate` subcommand + the sqlx/Postgres `just migrate-*` recipes.
//!   - `fingerprint [--model M]` — print the read model's content hash and exit.
//!     Read-only; take one before a risky deploy and compare after.
//!   - `verify [--model M] [--page-size N]` — **non-destructive.** Rebuild the read
//!     model into a staging namespace, compare it with the live one, throw the
//!     staged copy away, and exit non-zero on any divergence. The readiness Epic B
//!     drill, asserting §2's claim that projections are derived — safe to run on a
//!     timer against production.
//!   - `rebuild --yes [--model M] [--page-size N]` — the same run, but the staged
//!     copy is **promoted** (atomically, for Postgres) over the live one. The
//!     recovery procedure for a corrupted read model.
//!
//! `M` is `incidents` (Postgres), `dashboards` (ClickHouse analytics) or `all`.
//! Both need `EVENT_STORE_URL`. Only `rebuild` needs `--yes`, because only
//! `rebuild` changes the live model — `verify` cannot, which is what makes it
//! schedulable. See `docs/runbooks/projection-rebuild.md`.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clickhouse::Client;
use event_bus::{KafkaEventSink, PUBLISH_BACKOFF};
use rebuild::{ObservedReadModel, Snapshotter};
use secrecy::ExposeSecret;
use simulation::ch_migrate;
use simulation::config::ProjectionConfig;
use simulation::http;
use simulation::monitored_wallet_store::{MonitoredWalletStore, PgMonitoredWalletStore};
use simulation::projection_consumer::{build_consumer, ProjectionConsumer};
use simulation::rebuild::{PostgresStore, SimulationReadModel, Stores, Targets};
use simulation::store::{
    build_clickhouse_client, ClickhouseAnalytics, CrossChainFindingStore, PgIncidentStore,
    TimingStore, WalletExposureStore,
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env(
        "simulation-projection",
    ))?;
    let cfg = ProjectionConfig::from_env()?;

    // The binary owns the ClickHouse client; the migration runner and the analytics store
    // share it, but neither owns the connection lifecycle.
    let client = build_clickhouse_client(&cfg.clickhouse);

    // First positional arg selects the run mode; no arg runs the consumer.
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => run(cfg, client).await,
        Some("migrate") => {
            ch_migrate::MIGRATOR
                .cli(&client, args.next().as_deref())
                .await
        }
        Some(mode @ ("rebuild" | "verify" | "fingerprint")) => {
            run_rebuild(mode, RebuildArgs::parse(args)?, cfg, client).await
        }
        Some(other) => bail!(
            "unknown argument {other:?}; expected `migrate up|down|info`, \
             `fingerprint|rebuild|verify [--model incidents|dashboards|all] [--yes] [--page-size N]`, \
             or no args to run the consumer"
        ),
    }
}

/// Flags for the three projection-rebuild modes (readiness Epic B). Hand-parsed
/// to match this binary's existing `migrate` arm rather than pulling `clap` into
/// the service for three flags.
struct RebuildArgs {
    targets: Targets,
    /// Explicit authorization to **promote** — to replace the live read model
    /// with the staged one. Never defaulted, never inferred from a TTY. Only
    /// `rebuild` consults it; `verify` never promotes and so never needs it.
    confirmed: bool,
    page_size: u64,
}

impl RebuildArgs {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self> {
        let mut parsed = Self {
            targets: Targets::All,
            confirmed: false,
            page_size: rebuild::DEFAULT_PAGE,
        };
        let mut args = args.peekable();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--yes" => parsed.confirmed = true,
                "--model" => {
                    let raw = args.next().context("--model needs a value")?;
                    parsed.targets = Targets::parse(&raw).with_context(|| {
                        format!("unknown model {raw:?}; expected incidents|dashboards|all")
                    })?;
                }
                "--page-size" => {
                    parsed.page_size = args
                        .next()
                        .context("--page-size needs a value")?
                        .parse()
                        .context("--page-size must be a positive integer")?;
                }
                other => bail!("unknown flag {other:?}"),
            }
        }
        Ok(parsed)
    }
}

/// Connect the Postgres read model, for the rebuild modes that touch it.
async fn connect_postgres(cfg: &ProjectionConfig) -> Result<PostgresStore> {
    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    // The URL rides along because staging needs a *second* pool pointed at the
    // staging schema, and a pool cannot be re-pointed once built.
    Ok(PostgresStore::new(pool, cfg.postgres_url.clone()))
}

/// Bring the ClickHouse analytics schema up to date and hand the client back.
/// The schema must exist before the analytics tables can be scanned or
/// truncated — the same `up` the consumer boot path runs.
async fn migrated_clickhouse(client: Client) -> Result<Client> {
    ch_migrate::MIGRATOR
        .run(&client)
        .await
        .context("running ClickHouse analytics migrations")?;
    Ok(client)
}

/// Fingerprint / rebuild / verify the read model (readiness Epic B).
///
/// All three share one path because the *procedure* is one procedure; only the
/// verdict differs. `verify` exits non-zero on any divergence (the drill —
/// projections are supposed to be derived); `rebuild` reports the same diff as a
/// damage report and exits zero (the recovery — the event store is the system of
/// record, so the rebuilt state wins by definition).
async fn run_rebuild(
    mode: &str,
    args: RebuildArgs,
    cfg: ProjectionConfig,
    client: Client,
) -> Result<()> {
    // Connect only what this run touches — here rather than in `run()`, so a
    // fingerprint of one model does not require the other store to be up.
    // Building the `Stores` variant *is* the wiring: each arm connects exactly
    // what its target needs, so there is no "target selected but store missing"
    // state to check for afterwards.
    let stores = match args.targets {
        Targets::Postgres => Stores::Postgres(connect_postgres(&cfg).await?),
        Targets::Clickhouse => Stores::Clickhouse(migrated_clickhouse(client).await?),
        Targets::All => Stores::Both {
            postgres: connect_postgres(&cfg).await?,
            clickhouse: migrated_clickhouse(client).await?,
        },
    };
    // Wrapped once, here, so §19 metrics are the decorator's job and not a call
    // scattered through the procedure (conventions §14).
    let model = ObservedReadModel::new(SimulationReadModel::new(stores));

    if mode == "fingerprint" {
        let digest = rebuild::fingerprint(&model, &rebuild::Scope::everything())
            .await
            .context("fingerprinting the read model")?;
        println!(
            "{}: {} row(s)\nroot: {}",
            model.name(),
            digest.len(),
            digest.root().to_hex()
        );
        return Ok(());
    }

    let event_store_url = std::env::var("EVENT_STORE_URL")
        .context("EVENT_STORE_URL must name the event store to replay from")?;
    let source = rebuild::EventStoreReplay::new(&event_store_url)
        .context("building the event-store replay client")?;
    let plan = rebuild::RebuildPlan {
        scope: rebuild::Scope::everything(),
        page_size: args.page_size,
        confirmed: args.confirmed,
    };

    // A rebuild runs for minutes to hours; Ctrl-C / SIGTERM must stop it
    // cleanly, discarding the staging area rather than abandoning it.
    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::warn!(
                "shutdown signal received; the rebuild will stop and discard its staging area"
            );
            shutdown.cancel();
        }
    });

    tracing::info!(
        model = model.name(),
        event_store = %event_store_url,
        mode,
        "starting a projection rebuild into a staging namespace; the live read model stays \
         readable throughout and is replaced only on promotion"
    );

    let report = match mode {
        // The drill: build, compare, throw away. Never touches the live model,
        // so a divergence is the only thing that can fail it.
        "verify" => match rebuild::verify(&model, &source, &plan, &shutdown).await {
            Ok(report) => report,
            Err(rebuild::VerifyFailure::Diverged(report)) => {
                rebuild::observed::record_report(&report);
                println!("{}", report.summarize(20));
                bail!(
                    "the rebuilt read model differs from the live one — projections are NOT purely \
                     derived from the event store (see the diff above and \
                     docs/runbooks/projection-rebuild.md). The live model was NOT modified."
                );
            }
            Err(rebuild::VerifyFailure::Procedure(err)) => {
                rebuild::observed::record_failure(model.name());
                return Err(anyhow::Error::new(err).context("verifying the read model"));
            }
        },
        // The recovery: build, compare, promote. The diff is a damage report.
        _ => match rebuild::rebuild(&model, &source, &plan, &shutdown).await {
            Ok(report) => report,
            Err(err) => {
                rebuild::observed::record_failure(model.name());
                return Err(anyhow::Error::new(err).context("rebuilding the read model"));
            }
        },
    };

    rebuild::observed::record_report(&report);
    println!("{}", report.summarize(20));
    Ok(())
}

/// Run the consumer: apply pending ClickHouse migrations, connect the stores, then drain the
/// result topics until shutdown.
async fn run(cfg: ProjectionConfig, client: Client) -> Result<()> {
    telemetry::metrics::init(cfg.metrics_addr).context("starting the metrics exporter")?;

    tracing::info!(
        group = %cfg.group_id,
        "starting simulation incident/job projection consumer"
    );

    // Bring the analytics schema up to date before writing (Postgres schema is applied by
    // sqlx-cli via `just migrate-*` / the migrate.yml workflow — the same split as the
    // event store: schema is an operational step, distinct from running the service).
    ch_migrate::MIGRATOR
        .run(&client)
        .await
        .context("running ClickHouse analytics migrations")?;

    // Connect the two stores; a bad URL / unreachable database fails fast here at boot.
    let pool = db::connect(cfg.postgres_url.expose_secret())
        .await
        .context("connecting to Postgres")?;
    let pg_store = PgIncidentStore::new(pool.clone());
    let store = Arc::new(pg_store.clone());
    // Same pool, the §24 cross-chain-finding sibling seam (`PgIncidentStore`
    // implements both `IncidentStore` and `CrossChainFindingStore`, mirroring
    // `PgIntelligenceStore`'s multi-seam-over-one-pool shape).
    let cross_chain_store: Arc<dyn CrossChainFindingStore> = Arc::new(pg_store.clone());
    let analytics = ClickhouseAnalytics::new(client);
    analytics
        .ping()
        .await
        .context("probing ClickHouse analytics store")?;
    // Cheap to clone (the client is `Arc`-cheap, per `ClickhouseAnalytics`'s doc):
    // the consumer owns one handle for writes, the HTTP read API (§11 wallet
    // exposure, safe-block-timing) other handles for reads, all backed by the
    // same connection.
    let exposure_store: Arc<dyn WalletExposureStore> = Arc::new(analytics.clone());
    let timing_store: Arc<dyn TimingStore> = Arc::new(analytics.clone());
    let analytics = Arc::new(analytics);

    // The opt-in monitored-wallet list (§25, Sprint 15 t5) — shares the same
    // pool `pg_store` already connected above; the internal HTTP CRUD and the
    // scheduled report task below both read/write through this one handle.
    let monitored_wallets: Arc<dyn MonitoredWalletStore> =
        Arc::new(PgMonitoredWalletStore::new(pool));

    let shutdown = CancellationToken::new();
    // K8s probes (§20): /livez immediately; /readyz flips on once boot wiring
    // completes below. Opt-in via HEALTH_ADDR — unset (dev) serves nothing.
    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), shutdown.clone())
        .await
        .context("starting the health endpoints")?;
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    });

    // ── Kafka result-path projection (background task) ───────────────
    // A fatal consumer error cancels the token too, so the HTTP server drains
    // rather than serving reads against a process that stopped ingesting
    // (mirrors event-store's `serve()`).
    let consumer = build_consumer(&cfg.kafka_brokers, &cfg.group_id)
        .context("building the result-path Kafka consumer")?;
    // The uniform poison policy (§20): parked-not-lost, provisioned fail-fast.
    let dlq =
        event_bus::dlq::DeadLetterQueue::ensure_from_env(&cfg.kafka_brokers, "sim-projection")
            .await
            .context("provisioning the projection DLQ topic")?;
    let consumer_task = tokio::spawn({
        let shutdown = shutdown.clone();
        let cross_chain_store = cross_chain_store.clone();
        async move {
            let result = ProjectionConsumer::new(store, analytics, cross_chain_store)
                .run(consumer, PUBLISH_BACKOFF, Some(&dlq), &shutdown)
                .await;
            if let Err(ref err) = result {
                tracing::error!(error = %err, "projection consumer failed; initiating shutdown");
                shutdown.cancel();
            }
            result
        }
    });

    // ── Scheduled §25 exposure-report push (Sprint 15 t5, background task) ──
    // A `KafkaEventSink` is new to this binary — until now it only consumed;
    // this is its first producer seam. Each cycle publishes
    // `WalletExposureReportReady` (for notification to deliver) plus one
    // `WalletMonitored` usage fact per monitored wallet — both through the
    // same background at-least-once path `publish_resilient`/`UsageFact` give
    // every other producer, never the HTTP-hot-path `UsageRecorder`.
    let report_sink: Arc<dyn event_bus::EventSink> =
        Arc::new(KafkaEventSink::new(&cfg.kafka_brokers).context("building Kafka producer")?);
    let report_task = tokio::spawn({
        let monitored_wallets = Arc::clone(&monitored_wallets);
        let exposure_store = Arc::clone(&exposure_store);
        let shutdown = shutdown.clone();
        let interval = cfg.exposure_report_interval;
        async move {
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(interval) => {}
                }
                let period_end = Utc::now();
                let period_start = period_end - interval;
                match simulation::exposure_report::run_cycle(
                    monitored_wallets.as_ref(),
                    exposure_store.as_ref(),
                    report_sink.as_ref(),
                    period_start,
                    period_end,
                    PUBLISH_BACKOFF,
                    &shutdown,
                )
                .await
                {
                    Ok(stats) => tracing::info!(
                        published = stats.wallets_published,
                        failed = stats.wallets_failed,
                        "exposure-report cycle complete"
                    ),
                    Err(err) => tracing::warn!(
                        error = %err,
                        "scheduled exposure-report cycle failed; will retry next tick"
                    ),
                }
            }
        }
    });

    // ── Internal read API (§11 `/v1/incidents`, `/v1/wallet/{addr}/mev-exposure`,
    //    safe-block-timing `/v1/timing/recommendation`, `/v1/monitored-wallets`) ──
    let http_state = http::AppState {
        store: Arc::new(pg_store.clone()),
        pg: pg_store,
        exposure: exposure_store,
        timing: timing_store,
        monitored_wallets,
        cross_chain: cross_chain_store,
    };
    let listener = tokio::net::TcpListener::bind(cfg.http_addr)
        .await
        .with_context(|| format!("binding HTTP listener on {}", cfg.http_addr))?;
    tracing::info!(addr = %cfg.http_addr, "simulation-projection HTTP API listening");
    health.set_ready(true);

    axum::serve(listener, http::router(http_state))
        .with_graceful_shutdown({
            let shutdown = shutdown.clone();
            async move { shutdown.cancelled().await }
        })
        .await
        .context("HTTP server error")?;

    shutdown.cancel();
    let _ = report_task.await;
    let consumer_result = consumer_task.await.context("consumer task panicked")?;
    tracing::info!("simulation projection consumer shut down");
    consumer_result.context("projection consumer exited with error")
}

/// Resolve when the process receives Ctrl+C or (on Unix) SIGTERM.
async fn wait_for_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
