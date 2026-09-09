//! `loadtest` — offer load at a target throughput and decide whether the §6
//! fast path held (readiness Epic D).
//!
//! ```text
//! loadtest --profile crates/loadtest/profiles/mainnet-peak.json --headroom 1.5
//! ```
//!
//! Endpoints come from the environment so one binary serves docker-compose and
//! staging; everything about the *load* comes from the committed profile, so a
//! result is attributable to a reviewable file rather than to a shell history.
//!
//! The exit code is the deliverable (`0` held, `1` breached, `2` undecided) —
//! this runs as a nightly job, and a short-lived process is not reliably
//! scraped.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use loadtest::api::ApiLoad;
use loadtest::chain::ChainLoad;
use loadtest::profile::Profile;
use loadtest::run::CompositeSubject;
use loadtest::slo::Slo;
use loadtest::source::LoadSource;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    about = "Drive the platform at a target throughput and verify the §6 fast path holds < 1s p99 under load"
)]
struct Cli {
    /// The committed load profile to offer.
    #[arg(long, value_name = "PATH")]
    profile: PathBuf,
    /// Scale the offered rates. The readiness exit gate asks for 1.5× projected
    /// peak; the profile holds peak, this is the margin above it.
    #[arg(long, default_value_t = 1.0)]
    headroom: f64,
    /// Override the profile's measurement window, in seconds — for a smoke run
    /// that proves the harness is wired up without paying for a full run.
    #[arg(long, value_name = "SECONDS")]
    duration: Option<u64>,
    /// Budgets to judge against. Defaults to the crate's committed `slo.json`;
    /// there is deliberately no flag to *rewrite* it (see `slo`).
    #[arg(long, value_name = "PATH")]
    slo: Option<PathBuf>,
    /// Also write the report as JSON to this path.
    ///
    /// A separate file rather than a `--json` mode on stdout: a run takes
    /// minutes and must not have to be repeated to get the other rendering, and
    /// a second run would offer a second load and produce a different report.
    /// stdout stays the human text a red job is read by.
    #[arg(long, value_name = "PATH")]
    json_out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("loadtest"))?;
    let cli = Cli::parse();

    let mut profile = Profile::load(&cli.profile)?.with_headroom(cli.headroom);
    if let Some(seconds) = cli.duration {
        profile.duration = std::time::Duration::from_secs(seconds);
    }
    let slo = Slo::load(&cli.slo.unwrap_or_else(Slo::committed_path))?;
    let targets = Targets::from_env()?;

    // Ctrl-C stops the generator and lets the run report what it managed —
    // an interrupted run is a short run, and the sample-count and achieved-rate
    // checks decide whether that was enough to conclude anything.
    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::warn!("interrupted — stopping the generator and reporting");
                shutdown.cancel();
            }
        }
    });

    // Composition happens here, at the binary — the layer allowed to know that
    // the chain is Kafka and the subject is a Prometheus endpoint. Everything
    // below `run` sees only the seams.
    let http = reqwest::Client::builder()
        // A request that outlives the whole latency ladder is a failure, not a
        // sample: without a cap a stalled connection would hold a task open past
        // the end of the run and be counted as if it had answered.
        .timeout(Duration::from_secs(30))
        .build()
        .context("building the HTTP client")?;

    let sink: Arc<dyn event_bus::EventSink> = Arc::new(
        event_bus::KafkaEventSink::new(&targets.brokers)
            .context("connecting the block generator to Kafka")?,
    );

    let mut sources: Vec<Arc<dyn LoadSource>> =
        vec![Arc::new(ChainLoad::new(sink, profile.clone()))];
    if let Some(base) = &targets.api_base {
        sources.push(Arc::new(ApiLoad::new(
            http.clone(),
            base,
            targets.api_token.clone(),
            profile.clone(),
        )));
    }

    // Every replica of the subject, read as one: the SLO is stated over the
    // deployment (`sum by (le)`), and detection runs one instance per chain
    // (§20) with several replicas each under the HPA.
    let subject = CompositeSubject::new(http, &targets.detection_metrics)?;
    let report = loadtest::run::run(&profile, &slo, &sources, &subject, shutdown).await?;
    print!("{report}");
    if let Some(path) = &cli.json_out {
        std::fs::write(path, loadtest::report::to_json(&report)?)
            .with_context(|| format!("writing the JSON report to {}", path.display()))?;
    }

    let code = report.outcome() as i32;
    // Drop the telemetry guard before exiting so spans flush (cf. `copilot`).
    drop(_telemetry);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// Where the harness points. Endpoints, not a topology — the same binary runs
/// against docker-compose and against staging.
///
/// All optional but the broker and the metrics endpoint: those two *are* the
/// test, and defaulting them to a guess would let a misconfiguration run for the
/// full duration and report an empty histogram.
struct Targets {
    /// Kafka bootstrap servers the synthetic blocks are published to.
    brokers: String,
    /// Detection's `/metrics` URLs — the only place the §6 number exists.
    ///
    /// A list, because a real deployment has more than one pod and the budget
    /// is a property of all of them together. Comma-separated in the
    /// environment; one entry is the local case, not a special case.
    detection_metrics: Vec<String>,
    /// The public API's base URL. Absent means no API driver is built at all,
    /// which the gates report differently from a driver that ran and lagged.
    api_base: Option<String>,
    /// Bearer token for the API driver. Without one every request is a 401,
    /// which is fast and meaningless — the success-ratio gate catches it.
    api_token: Option<String>,
}

impl Targets {
    fn from_env() -> Result<Self> {
        Ok(Self {
            brokers: telemetry::env::required("KAFKA_BROKERS")
                .context("the block generator needs a broker to publish to")?,
            detection_metrics: std::env::var("LOADTEST_DETECTION_METRICS_URL")
                .unwrap_or_else(|_| "http://localhost:9100/metrics".to_owned())
                .split(',')
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(str::to_owned)
                .collect(),
            api_base: std::env::var("LOADTEST_API_BASE_URL").ok(),
            api_token: std::env::var("LOADTEST_API_TOKEN").ok(),
        })
    }
}
