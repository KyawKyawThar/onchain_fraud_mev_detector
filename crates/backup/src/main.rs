//! `backup` — the CLI and the scheduled agent behind readiness Epic B.
//!
//! ```text
//! backup snapshot    [--target …]     take one consistent snapshot
//! backup list        [--target …]     what is on disk, and how old
//! backup fingerprint [--target …]     what is in the LIVE store right now (read-only)
//! backup verify      [--target …]     checksums only — NOT a restore
//! backup drill       [--target …]     restore into a throwaway db and prove it (NON-DESTRUCTIVE)
//! backup report                       RPO/RTO against the budgets; non-zero exit on breach
//! backup restore --target … --into …  the recovery. Requires --yes.
//! backup prune       [--target …]     retention; never removes the newest artifact
//! backup serve                        the scheduled agent: snapshots, drills, /metrics, /livez
//! ```
//!
//! ## Why `serve` exists and a CronJob does not
//!
//! A CronJob cannot report that it did not run. Delete it, scale it away, let
//! its image fail to pull, and the metric it would have written simply is not
//! there — indistinguishable, on a dashboard, from healthy. The gauges that
//! matter here are *ages* ("seconds since the newest artifact's cut"), and an
//! age has to be published by something that is alive. So `serve` holds the
//! timers, exports the objective report every cycle, and is itself covered by
//! `up{job="backup"}`.
//!
//! ## Exit codes
//!
//! `0` success. `1` a run failed. **`2` a drill diverged or an objective is
//! breached** — separated so CI and a pager can distinguish "the tool broke"
//! from "the tool worked and the answer is bad".

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use backup::artifact::{verify_artifact, ArtifactStore, DrillRecord};
use backup::config::Config;
use backup::objective::humanize;
use backup::target::{BackupTarget, Database};
use backup::{drill, measure, observed, snapshot};
use chrono::Utc;
use clap::{Parser, Subcommand};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Exit code for "the tool worked; the answer is a failure".
const EXIT_BAD_ANSWER: u8 = 2;
/// How many divergent rows/tables to print before truncating.
const DIFF_LIMIT: usize = 20;
/// How often the agent republishes the objective gauges and re-evaluates
/// whether a job is due. Fast, because it does no work of its own.
const HEARTBEAT: Duration = Duration::from_secs(30);
/// How long a shutdown waits for an in-flight snapshot or drill to notice the
/// cancellation and unwind. Slightly under a typical 60s pod grace period, so
/// the drain finishes before `SIGKILL` rather than being cut off by it.
const DRAIN_GRACE: Duration = Duration::from_secs(45);

#[derive(Parser)]
#[command(
    name = "backup",
    about = "Backups with a tested restore, and the RPO/RTO they measure",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Restrict to one target (`postgres`, `clickhouse`). Default: all
    /// configured targets.
    #[arg(long, global = true)]
    target: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Take one consistent snapshot per target.
    Snapshot,
    /// List artifacts on disk with their ages.
    List,
    /// Print what is in the live store right now. Read-only by construction —
    /// it is handed a `StoreReader`, which cannot restore or drop anything.
    Fingerprint,
    /// Recompute artifact checksums. Proves the bytes are intact — it does
    /// *not* prove they restore. Use `drill` for that.
    Verify,
    /// Restore the newest artifact into a throwaway database, verify it
    /// row-for-row, and drop it. Non-destructive; safe against production.
    Drill {
        /// Leave the restored copy in place for inspection. It is swept once
        /// it ages out, so this is a delay, not a permanent leak.
        #[arg(long)]
        keep: bool,
    },
    /// Measure RPO/RTO against the configured budgets.
    Report,
    /// The recovery. Restores an artifact into a named database.
    Restore {
        /// Artifact id. Defaults to the newest.
        #[arg(long)]
        artifact: Option<String>,
        /// Database to restore into. Must already exist and be empty.
        #[arg(long)]
        into: String,
        /// Required. This writes to a database you named.
        #[arg(long)]
        yes: bool,
    },
    /// Apply the retention policy.
    Prune,
    /// Run snapshots and drills on a timer, exporting `/metrics`.
    Serve,
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("backup: cannot start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("backup: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let _telemetry = telemetry::init(telemetry::TelemetryConfig::from_env("backup"))
        .context("initialising telemetry")?;

    let config = Config::from_env()?;
    let store = ArtifactStore::new(&config.root);
    let targets = select_targets(&config, cli.target.as_deref())?;
    // One-shot commands cancel on Ctrl-C too: a `pg_dump` child of an
    // interrupted CLI run would otherwise outlive the terminal that started it.
    let cancel = CancellationToken::new();
    watch_for_interrupt(cancel.clone());

    match cli.command {
        Command::Snapshot => {
            for target in &targets {
                let manifest = snapshot(target.as_ref(), &store, &cancel).await?;
                println!(
                    "{}: {} table(s), {} row(s), {} bytes, cut at {}",
                    manifest.target,
                    manifest.tables.len(),
                    manifest.rows(),
                    manifest.bytes(),
                    manifest.cut_at
                );
                for note in manifest.incompleteness() {
                    println!("    ! {note}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::List => {
            let now = Utc::now();
            for target in &targets {
                for artifact in store.list(target.name()).await? {
                    println!(
                        "{:<40} {:>10} old  {:>12} bytes  {:>10} rows{}",
                        artifact.manifest.artifact_id,
                        humanize(artifact.age(now)),
                        artifact.manifest.bytes(),
                        artifact.manifest.rows(),
                        if artifact.manifest.is_complete() {
                            String::new()
                        } else {
                            "  INCOMPLETE".to_owned()
                        }
                    );
                    for note in &artifact.manifest.notes {
                        println!("    - {note}");
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Fingerprint => {
            for target in &targets {
                // `as_ref()` hands over the read-only half of the seam.
                let live = target.live();
                let tables = backup::fingerprint(target.as_ref(), &live).await?;
                println!("{} ({live}):", target.name());
                for (table, print) in &tables {
                    println!("    {table:<40} {:>10} rows  {}", print.rows, print.content);
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Verify => {
            let mut bad = false;
            for target in &targets {
                for artifact in store.list(target.name()).await? {
                    let problems = verify_artifact(&artifact).await?;
                    if problems.is_empty() {
                        println!("{}: intact", artifact.manifest.artifact_id);
                    } else {
                        bad = true;
                        println!("{}: DAMAGED", artifact.manifest.artifact_id);
                        for problem in problems {
                            println!("    ! {problem}");
                        }
                    }
                }
            }
            println!(
                "\nnote: this checked bytes, not restorability. `backup drill` is the control."
            );
            Ok(bad_answer_if(bad))
        }

        Command::Drill { keep } => {
            let mut failed = false;
            for target in &targets {
                let report = drill::run_latest(target.as_ref(), &store, keep, &cancel).await?;
                observed::record_drill(&report);
                println!("{}", report.summarize(DIFF_LIMIT));
                failed |= !report.passed();
            }
            Ok(bad_answer_if(failed))
        }

        Command::Report => {
            let names: Vec<String> = targets.iter().map(|t| t.name().to_owned()).collect();
            let report = measure(&names, &store, config.objective).await?;
            observed::record_report(&report);
            print!("{}", report.render());
            Ok(bad_answer_if(!report.is_met()))
        }

        Command::Restore {
            artifact,
            into,
            yes,
        } => {
            anyhow::ensure!(
                yes,
                "refusing to restore without --yes: this writes into the database you named"
            );
            let target = one_target(&targets)?;
            let artifact = match artifact {
                Some(id) => store.find(target.name(), &id).await?,
                None => store
                    .newest(target.name())
                    .await?
                    .context("no artifact to restore")?,
            };

            let problems = verify_artifact(&artifact).await?;
            anyhow::ensure!(
                problems.is_empty(),
                "refusing to restore a damaged artifact:\n  {}",
                problems.join("\n  ")
            );
            for note in artifact.manifest.incompleteness() {
                // Not a refusal — the operator has already lost the original
                // and needs whatever this holds — but they must know going in.
                eprintln!("WARNING: this artifact is incomplete: {note}");
            }

            // A named destination is deliberately *not* a `Scratch`: the
            // operator is restoring somewhere real, and nothing in this crate
            // may later decide such a database is safe to drop. There is no
            // way to spell that conversion.
            let destination = Database::new(into)?;
            let started = std::time::Instant::now();
            target
                .restore(&artifact.dir, &artifact.manifest, &destination, &cancel)
                .await?;
            let fingerprints = target.fingerprint(&destination).await?;
            let diff = artifact.manifest.diff(&fingerprints);
            println!(
                "restored {} into {} in {} — {}",
                artifact.manifest.artifact_id,
                destination,
                humanize(started.elapsed()),
                diff.summarize(DIFF_LIMIT)
            );
            // A divergence here is a damage report, not a refusal: the
            // operator has already lost the original, and needs to know
            // exactly what came back rather than be told to try again.
            Ok(bad_answer_if(!diff.is_clean()))
        }

        Command::Prune => {
            for target in &targets {
                let removed = store.prune(target.name(), config.retention).await?;
                println!("{}: pruned {} artifact(s)", target.name(), removed.len());
                for id in removed {
                    println!("    - {id}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Serve => serve(config, store, targets, cancel).await,
    }
}

/// One long-running job, and the slot that keeps exactly one of it in flight.
///
/// This is the piece that fixes the original design's real bug. The first cut
/// ran a snapshot *inline in a `select!` arm*, so for the hours a production
/// `pg_dump` takes: the objective gauges could not be republished, `SIGTERM`
/// could not be observed, and `tokio::time::interval`'s default `Burst`
/// behaviour then fired every missed tick back-to-back. A backup agent whose
/// RPO gauge freezes during the longest operation — while Prometheus happily
/// scrapes the stale value — is the exact "monitoring the monitor" failure the
/// conventions warn about, self-inflicted.
struct JobSlot {
    job: &'static str,
    handle: Option<JoinHandle<()>>,
}

impl JobSlot {
    fn new(job: &'static str) -> Self {
        Self { job, handle: None }
    }

    fn is_running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    fn start(&mut self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        self.handle = Some(tokio::spawn(future));
    }

    /// Wait for the in-flight job, bounded. Returns false if it did not finish
    /// in time — reported rather than waited on forever, because a shutdown
    /// that hangs is killed instead of drained.
    async fn drain(&mut self, grace: Duration) -> bool {
        let Some(handle) = self.handle.take() else {
            return true;
        };
        match tokio::time::timeout(grace, handle).await {
            Ok(_) => true,
            Err(_) => {
                tracing::warn!(
                    job = self.job,
                    "did not finish within the drain grace period"
                );
                false
            }
        }
    }
}

/// Is a snapshot due for `target`?
///
/// **State, not a timer.** The question is "is the newest artifact older than
/// the cadence?", which makes the trigger idempotent: a restart does not lose
/// the schedule, a crash-loop cannot hammer production with a full `pg_dump`
/// per restart, and a missed cycle is simply caught up on the next heartbeat
/// rather than replayed as a burst. It is the same principle the gauges are
/// built on — read the world, do not trust a clock.
async fn snapshot_due(store: &ArtifactStore, target: &str, cadence: Duration) -> bool {
    match store.newest(target).await {
        Ok(Some(artifact)) => artifact.age(Utc::now()) >= cadence,
        Ok(None) => true,
        // Unreadable store: attempt it, and let the snapshot report the real
        // error rather than silently doing nothing.
        Err(err) => {
            tracing::warn!(target, error = %err, "could not read the artifact store");
            true
        }
    }
}

/// Is a drill due? Paced on the newest attempt of **any** outcome, so a
/// persistently failing drill runs once per cadence instead of on every
/// heartbeat — hammering a store that is already unhealthy is not diagnosis.
async fn drill_due(store: &ArtifactStore, target: &str, cadence: Duration) -> bool {
    // You cannot drill what does not exist. Without this, a fresh deployment
    // (or one whose snapshots are failing) logs an ERROR per cadence for a
    // condition `BackupRpoBreached` already covers — the drill is not failing,
    // it has nothing to run against.
    if !matches!(store.newest(target).await, Ok(Some(_))) {
        return false;
    }
    match DrillRecord::newest_attempt(store, target).await {
        Ok(Some(record)) => (Utc::now() - record.finished_at)
            .to_std()
            .is_ok_and(|age| age >= cadence),
        Ok(None) => true,
        Err(err) => {
            tracing::warn!(target, error = %err, "could not read drill history");
            true
        }
    }
}

/// The scheduled agent.
///
/// One fast heartbeat that only publishes gauges and decides what is due;
/// every unit of real work runs on its own task. See [`JobSlot`].
async fn serve(
    config: Config,
    store: ArtifactStore,
    targets: Vec<Arc<dyn BackupTarget>>,
    cancel: CancellationToken,
) -> Result<ExitCode> {
    anyhow::ensure!(
        !targets.is_empty(),
        "no targets configured — set DATABASE_URL and/or the CLICKHOUSE_* variables"
    );

    let metrics_addr = telemetry::env::parse_or("BACKUP_METRICS_ADDR", "0.0.0.0:9112".to_owned())?
        .parse()
        .context("BACKUP_METRICS_ADDR is not a valid socket address")?;
    telemetry::metrics::init(metrics_addr)?;

    let health = telemetry::health::HealthState::new();
    telemetry::health::spawn_from_env(health.clone(), cancel.clone()).await?;
    health.set_ready(true);

    let names: Vec<String> = targets.iter().map(|t| t.name().to_owned()).collect();
    tracing::info!(
        targets = ?names,
        root = %store.root().display(),
        snapshot_interval_s = config.snapshot_interval.as_secs(),
        drill_interval_s = config.drill_interval.as_secs(),
        rpo_s = config.objective.rpo.as_secs(),
        rto_s = config.objective.rto.as_secs(),
        "backup agent starting"
    );

    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    // Never replay missed ticks as a burst. It barely matters for a heartbeat
    // this cheap, and it is set anyway so a descheduled process cannot produce
    // a thundering catch-up if this loop ever grows heavier.
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut snapshots = JobSlot::new("snapshot");
    let mut drills = JobSlot::new("drill");

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                // 1. Publish first, unconditionally. These gauges are the
                //    product; nothing below may delay them.
                match measure(&names, &store, config.objective).await {
                    Ok(report) => {
                        observed::record_report(&report);
                        for breach in report.breaches() {
                            tracing::warn!(breach = %breach, "recovery objective breached");
                        }
                    }
                    Err(err) => tracing::error!(error = %err, "could not measure the objectives"),
                }

                // 2. Spawn what is due and not already running.
                if !snapshots.is_running() {
                    let mut due = Vec::new();
                    for target in &targets {
                        if snapshot_due(&store, target.name(), config.snapshot_interval).await {
                            due.push(Arc::clone(target));
                        }
                    }
                    if !due.is_empty() {
                        snapshots.start(snapshot_cycle(
                            due,
                            store.clone(),
                            config.retention,
                            cancel.clone(),
                        ));
                    }
                } else {
                    for target in &targets {
                        if snapshot_due(&store, target.name(), config.snapshot_interval).await {
                            observed::record_skipped_cycle(target.name(), "snapshot");
                        }
                    }
                }

                if !drills.is_running() {
                    let mut due = Vec::new();
                    for target in &targets {
                        if drill_due(&store, target.name(), config.drill_interval).await {
                            due.push(Arc::clone(target));
                        }
                    }
                    if !due.is_empty() {
                        drills.start(drill_cycle(due, store.clone(), cancel.clone()));
                    }
                } else {
                    for target in &targets {
                        if drill_due(&store, target.name(), config.drill_interval).await {
                            observed::record_skipped_cycle(target.name(), "drill");
                        }
                    }
                }
            }
            () = cancel.cancelled() => {
                tracing::info!("shutdown requested, draining");
                break;
            }
        }
    }

    health.set_ready(false);
    // The in-flight jobs already saw the cancellation through the token, which
    // is what makes this a drain and not a wait.
    let drained = snapshots.drain(DRAIN_GRACE).await & drills.drain(DRAIN_GRACE).await;
    if !drained {
        tracing::warn!("exiting with work still in flight");
    }
    Ok(ExitCode::SUCCESS)
}

/// One snapshot pass over the due targets, then retention.
async fn snapshot_cycle(
    targets: Vec<Arc<dyn BackupTarget>>,
    store: ArtifactStore,
    retention: Duration,
    cancel: CancellationToken,
) {
    for target in &targets {
        match snapshot(target.as_ref(), &store, &cancel).await {
            Ok(_) => {}
            Err(err) if err.is_cancelled() => {
                tracing::info!(target = target.name(), "snapshot cancelled by shutdown");
                return;
            }
            Err(err) => {
                // The classification is the whole point: a transient failure
                // is a log line, a permanent one is an alert that fires long
                // before the RPO budget would have caught it.
                if err.is_permanent() {
                    tracing::error!(
                        target = target.name(),
                        error = %err,
                        "snapshot failed permanently — it will keep failing until someone acts"
                    );
                } else {
                    tracing::warn!(target = target.name(), error = %err, "snapshot failed, will retry");
                }
            }
        }
    }
    for target in &targets {
        match store.prune(target.name(), retention).await {
            Ok(removed) if !removed.is_empty() => {
                tracing::info!(
                    target = target.name(),
                    pruned = removed.len(),
                    "retention applied"
                );
            }
            Ok(_) => {}
            Err(err) => tracing::error!(target = target.name(), error = %err, "prune failed"),
        }
    }
}

/// One drill pass over the due targets.
async fn drill_cycle(
    targets: Vec<Arc<dyn BackupTarget>>,
    store: ArtifactStore,
    cancel: CancellationToken,
) {
    for target in &targets {
        match drill::run_latest(target.as_ref(), &store, false, &cancel).await {
            Ok(report) => {
                observed::record_drill(&report);
                observed::record_sweep(target.name(), report.swept.len());
                if report.passed() {
                    tracing::info!(
                        target = target.name(),
                        elapsed_s = report.elapsed.as_secs_f64(),
                        "restore drill passed"
                    );
                } else {
                    tracing::error!(
                        target = target.name(),
                        failures = ?report.failures(),
                        "restore drill FAILED — the backup is not restorable as claimed"
                    );
                }
            }
            Err(err) if err.is_cancelled() => {
                tracing::info!(target = target.name(), "drill cancelled by shutdown");
                return;
            }
            Err(err) => {
                observed::record_drill_failure(target.name(), &err);
                tracing::error!(target = target.name(), error = %err, "restore drill could not run");
            }
        }
    }
}

/// Cancel on SIGTERM or Ctrl-C, once, for every subcommand.
fn watch_for_interrupt(cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(sigterm) => sigterm,
                Err(err) => {
                    tracing::warn!(error = %err, "cannot listen for SIGTERM");
                    return;
                }
            };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received"),
            _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
        }
        cancel.cancel();
    });
}

fn select_targets(config: &Config, wanted: Option<&str>) -> Result<Vec<Arc<dyn BackupTarget>>> {
    let all = config.targets()?;
    let Some(wanted) = wanted else {
        anyhow::ensure!(
            !all.is_empty(),
            "no targets configured — set DATABASE_URL and/or the CLICKHOUSE_* variables"
        );
        return Ok(all);
    };
    let names: Vec<String> = all.iter().map(|t| t.name().to_owned()).collect();
    let selected: Vec<Arc<dyn BackupTarget>> =
        all.into_iter().filter(|t| t.name() == wanted).collect();
    anyhow::ensure!(
        !selected.is_empty(),
        "no configured target named {wanted:?} (configured: {names:?})"
    );
    Ok(selected)
}

fn one_target(targets: &[Arc<dyn BackupTarget>]) -> Result<&dyn BackupTarget> {
    anyhow::ensure!(
        targets.len() == 1,
        "this command acts on one store — pass --target"
    );
    Ok(targets[0].as_ref())
}

fn bad_answer_if(bad: bool) -> ExitCode {
    if bad {
        ExitCode::from(EXIT_BAD_ANSWER)
    } else {
        ExitCode::SUCCESS
    }
}
