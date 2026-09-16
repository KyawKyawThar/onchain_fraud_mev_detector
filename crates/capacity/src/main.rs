//! `capacity` — price the platform's ClickHouse and Kafka growth and judge the
//! decisions that are expensive to change later (readiness Epic D).
//!
//! ```text
//! capacity                        # the committed model, at 1× — the plan
//! capacity --headroom 1.5         # the gate CI holds (tests/committed.rs)
//! capacity --evidence-days 3653   # what a ten-year retention policy would cost
//! capacity --partition-by "(chain, event_type, toDate(occurred_at))"   # the original key
//! ```
//!
//! Exit code `0` held, `1` breached. Every input is a committed file, so a run
//! is reproducible from a commit and needs no running stack.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use capacity::key::PartitionKey;
use capacity::model::Model;
use capacity::units::Positive;
use capacity::{checks, corpus, ddl, plan, report};
use clap::Parser;

#[derive(Parser)]
#[command(
    about = "Model ClickHouse partitions, shards and storage growth and Kafka placement, and gate the key decisions"
)]
struct Cli {
    /// The capacity profile. Defaults to the crate's committed `model.json`.
    #[arg(long, value_name = "PATH")]
    model: Option<PathBuf>,
    /// Scale the load (the readiness exit gate's 1.5×).
    #[arg(long, default_value_t = 1.0)]
    headroom: f64,
    /// Evidence window in days. Defaults to the retention policy's.
    #[arg(long, value_name = "DAYS")]
    evidence_days: Option<u32>,
    /// The event schema corpus row sizes are measured from.
    #[arg(long, value_name = "DIR")]
    corpus: Option<PathBuf>,
    /// The crates whose `migrations/` are replayed.
    #[arg(long, value_name = "DIR")]
    crates: Option<PathBuf>,
    /// Price the event store under a different partition key — a what-if.
    #[arg(long, value_name = "EXPR")]
    partition_by: Option<String>,
    /// Also write the plan and findings as JSON.
    #[arg(long, value_name = "PATH")]
    json_out: Option<PathBuf>,
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    let model = Model::load(&cli.model.unwrap_or_else(capacity::committed_model_path))?;
    let shapes = corpus::load(&cli.corpus.unwrap_or_else(capacity::default_corpus_dir))?;
    let tables = ddl::replay_workspace(&cli.crates.unwrap_or_else(capacity::default_crates_dir))?;
    let inputs = plan::Inputs {
        model: &model,
        shapes: &shapes,
        tables: &tables,
        evidence_days: cli
            .evidence_days
            .unwrap_or_else(|| retention::PolicySet::default().widest_evidence_days()),
        events_key_override: cli
            .partition_by
            .as_deref()
            .map(PartitionKey::parse)
            .transpose()?,
    };
    let headroom = Positive::new(cli.headroom).map_err(anyhow::Error::msg)?;
    let plan = plan::plan(&inputs, headroom)?;
    let findings = checks::judge(&model, &plan);
    print!("{}", report::render(&plan, &model, &findings));

    if let Some(path) = cli.json_out {
        let json = serde_json::json!({ "plan": plan, "findings": findings });
        std::fs::write(&path, serde_json::to_vec_pretty(&json)?)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(if checks::has_breach(&findings) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
