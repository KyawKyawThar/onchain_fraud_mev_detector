//! `dataset` — export a labeled training set from an event-store window
//! (§20.1, Sprint 18 t2).
//!
//! ```text
//!   dataset export --from 2026-08-01T00:00:00Z --to 2026-08-02T00:00:00Z \
//!                  --parquet out/sandwich-aug01.parquet --clickhouse
//!   dataset migrate up|down|info
//! ```
//!
//! Every flag that changes *which rows come out* is folded into the
//! `DatasetSpec` and therefore into the `dataset_id` — so two invocations that
//! print the same id produced the same dataset, and two that print the same
//! `content_hash` produced it byte for byte. Flags that only change *where the
//! rows go* (`--parquet`, `--clickhouse`) are deliberately outside both.
//!
//! With no sink flag the run is a dry run: it replays, joins, extracts and
//! prints the manifest without writing anywhere — the cheap way to see what a
//! window would yield before committing a table to it.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use dataset::config::Config;
use dataset::ctx::{Fidelity, ReplayCtxFactory};
use dataset::sink::clickhouse::{build_client, ClickHouseSink};
use dataset::sink::parquet::ParquetSink;
use dataset::sink::{CollectingSink, FanOutSink};
use dataset::source::HttpEventSource;
use dataset::spec::DatasetSpec;
use dataset::{run_export, ExportOptions};
use events::primitives::Chain;
use ml_features::{FeatureVersion, Granularity};

#[derive(Parser)]
#[command(
    name = "dataset",
    about = "Replay an event-store window into a labeled (features, label) training set (§20.1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Materialise a dataset from a replay window.
    Export(ExportArgs),
    /// Apply, revert or inspect this binary's ClickHouse migrations.
    Migrate {
        /// `up`, `down`, or `info`.
        action: String,
    },
}

#[derive(clap::Args)]
struct ExportArgs {
    // ── the dataset's identity (everything here is in the dataset_id) ──
    /// Chain id to replay (1 = Ethereum).
    #[arg(long, default_value_t = 1)]
    chain: u64,
    /// Inclusive start of the window (RFC 3339, e.g. 2026-08-01T00:00:00Z).
    #[arg(long)]
    from: DateTime<Utc>,
    /// Exclusive end of the window — half-open, so adjacent windows tile.
    #[arg(long)]
    to: DateTime<Utc>,
    /// Feature schema version to extract under. Defaults to the current one;
    /// an older version regenerates an older dataset, provided this build still
    /// ships its extractor.
    #[arg(long)]
    feature_version: Option<u32>,
    /// One row per implicated transaction (`tx`) or per finding (`block`).
    #[arg(long, default_value = "tx", value_parser = ["tx", "block"])]
    granularity: String,
    /// Lowest context fidelity a row may be built from. `full_bundle` or better
    /// is what a *trainable* dataset needs; the looser levels exist for
    /// inspecting what a window holds.
    #[arg(long, default_value = "header_only",
          value_parser = ["header_only", "partial_bundle", "full_bundle", "enriched"])]
    min_fidelity: String,
    /// Keep findings whose alert binding was ambiguous. Off by default: a
    /// mislabeled row is worse for a model than a missing one.
    #[arg(long)]
    include_ambiguous: bool,
    /// Seconds past `--to` to keep reading events, so findings near the end of
    /// the window still see their simulation outcome. Without this a window's
    /// labels depend on where it happens to end, and adjacent windows do not
    /// compose. Set it to the simulation SLA plus finality depth.
    #[arg(long, default_value_t = dataset::DEFAULT_LOOKAHEAD_SECS)]
    lookahead_secs: u64,

    // ── destinations (deliberately NOT part of the dataset's identity) ──
    /// Write a Parquet file here, plus a `<path>.manifest.json` sidecar.
    #[arg(long)]
    parquet: Option<std::path::PathBuf>,
    /// Write to the ClickHouse `ml_dataset_rows` / `ml_dataset_manifests`
    /// tables (migrations are applied first).
    #[arg(long)]
    clickhouse: bool,
    /// Also write the manifest to this path as JSON.
    #[arg(long)]
    manifest: Option<std::path::PathBuf>,

    // ── run knobs (these must not change the dataset) ──────────────────
    /// Ceiling on events held in memory for one shard's replay.
    #[arg(long, default_value_t = dataset::export::DEFAULT_MAX_EVENTS)]
    max_events: usize,
    /// Export the window in consecutive sub-windows of this many seconds,
    /// bounding peak memory by the shard rather than the window. Produces
    /// byte-identical output to an unsharded run — that is what the lookahead
    /// and the streaming digest are for. Unset means one shard.
    #[arg(long)]
    shard_secs: Option<i64>,
    /// Refuse the export if more than this fraction of labeled findings had no
    /// usable context. Those drops correlate with busy blocks, so a high rate
    /// biases the dataset toward quiet ones — a silent failure worth turning
    /// into a loud one. `1.0` disables the gate.
    #[arg(long, default_value_t = 0.25)]
    max_drop_fraction: f64,
    /// Serve Prometheus metrics on this address for the duration of the run
    /// (§19). Unset means the `metrics` call sites stay no-ops.
    #[arg(long)]
    metrics_addr: Option<std::net::SocketAddr>,
}

impl ExportArgs {
    fn spec(&self) -> Result<DatasetSpec> {
        Ok(DatasetSpec {
            chain: Chain(self.chain),
            from: self.from,
            to: self.to,
            feature_version: self
                .feature_version
                .map_or(ml_features::FEATURE_VERSION, FeatureVersion),
            granularity: match self.granularity.as_str() {
                "block" => Granularity::Block,
                _ => Granularity::Tx,
            },
            min_fidelity: Fidelity::parse(&self.min_fidelity)
                .with_context(|| format!("unknown fidelity {:?}", self.min_fidelity))?,
            include_ambiguous: self.include_ambiguous,
            lookahead_secs: self.lookahead_secs,
        })
    }

    fn options(&self) -> ExportOptions {
        ExportOptions {
            max_events: self.max_events,
            shard: self.shard_secs.map(chrono::Duration::seconds),
            // `1.0` (or anything at/above it) means "never gate": a fraction
            // cannot exceed 1, so the check can never fire.
            max_drop_fraction: (self.max_drop_fraction < 1.0).then_some(self.max_drop_fraction),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Hold the guard for the lifetime of `main` so spans flush on exit (§19).
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("dataset"))?;
    let cli = Cli::parse();
    let config = Config::from_env().context("reading configuration from the environment")?;

    match cli.command {
        Command::Migrate { action } => {
            let client = build_client(&config.clickhouse);
            dataset::migrate::MIGRATOR.cli(&client, Some(&action)).await
        }
        Command::Export(args) => export(args, config).await,
    }
}

async fn export(args: ExportArgs, config: Config) -> Result<()> {
    // Opt-in, like every other service's exporter: unset means the `metrics`
    // call sites stay no-ops and nothing binds a port. Installed before the run
    // so a long sharded export is scrapeable *while* it works, not only after.
    if let Some(addr) = args.metrics_addr {
        telemetry::metrics::init(addr).context("installing the Prometheus exporter")?;
    }

    let spec = args.spec()?;
    // Fail on a bad window or an unshipped feature version *before* opening a
    // file or touching a database (the link-or-fail discipline).
    spec.validate().context("validating the dataset spec")?;

    let extractor = ml_features::extractor_for(spec.feature_version).expect("validated above");
    let feature_names: Vec<String> = extractor
        .schema(spec.granularity)
        .names()
        .map(str::to_owned)
        .collect();

    let mut sinks = FanOutSink::new();
    if args.clickhouse {
        let client = build_client(&config.clickhouse);
        dataset::migrate::MIGRATOR
            .run(&client)
            .await
            .context("applying the dataset ClickHouse migrations")?;
        let sink = ClickHouseSink::new(client);
        sink.ping()
            .await
            .context("ClickHouse is not reachable — refusing to replay a window we cannot write")?;
        sinks.push(Box::new(sink));
    }
    if let Some(path) = &args.parquet {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        sinks.push(Box::new(
            ParquetSink::create(path, feature_names.clone())
                .with_context(|| format!("creating {}", path.display()))?,
        ));
    }

    let dry_run = sinks.is_empty();
    if dry_run {
        // Nothing to write to: still run the whole pipeline so the manifest is
        // real, just keep the rows in memory.
        sinks.push(Box::new(CollectingSink::new()));
    }

    let http = reqwest::Client::builder()
        // A per-request timeout: without one, a half-open connection to a dead
        // event-store pod hangs the export forever — the failure the retry
        // policy cannot see, because no error is ever returned.
        .timeout(dataset::source::DEFAULT_REQUEST_TIMEOUT)
        .build()
        .context("building the event-store HTTP client")?;
    let events = HttpEventSource::new(http, &config.event_store_url);

    // Today's context source is reconstructed from each shard's own window, so
    // the factory rebuilds it per shard. When an archive-backed `CtxSource`
    // lands it becomes a `StaticCtxFactory` built from config, and nothing else
    // here changes.
    let ctx_factory = ReplayCtxFactory;

    let manifest = run_export(&spec, &events, &ctx_factory, &mut sinks, args.options())
        .await
        .context("exporting the dataset")?;

    dataset::metrics::record_export(&manifest);

    if let Some(path) = &args.manifest {
        std::fs::write(path, serde_json::to_string_pretty(&manifest)?)
            .with_context(|| format!("writing {}", path.display()))?;
    }

    print!("{}", manifest.summary());
    if dry_run {
        println!("  (dry run — no sink selected; pass --clickhouse and/or --parquet to write)");
    }
    if manifest.rows.written == 0 {
        // Not an error: an empty window, or a window whose findings were all
        // excluded, is a legitimate answer. But it is worth saying out loud,
        // because the manifest's `dropped` line is where the reason is.
        println!("  note: no rows were written — see the dropped/outcome counts above");
    }
    Ok(())
}
