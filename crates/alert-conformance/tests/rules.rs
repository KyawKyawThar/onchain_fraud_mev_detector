//! The I/O shell: feed the real `deploy/prometheus-rules.yml` through the pure
//! rules in the lib. Runs under plain `cargo test`/nextest, so an alert that
//! cannot fire fails the same gate locally and in CI.
//!
//! Reading the deployed file rather than a fixture is the whole point. A
//! fixture would test the rules; this tests the deployment — and since the
//! Kubernetes ConfigMap is generated from this same file by
//! `deploy/k8s/base/kustomization.yaml`, checking it here covers both targets.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use yaml_rust2::{Yaml, YamlLoader};

/// The repo root, resolved from this crate's manifest dir so every path below
/// is independent of the working directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repo root exists relative to this crate")
}

fn rules_path() -> PathBuf {
    repo_root().join("deploy/prometheus-rules.yml")
}

/// Read each [`BatchSeries`]' cadence out of the CronJob manifest that declares
/// it, rather than trusting a number restated in Rust.
///
/// A schedule this cannot classify is deliberately left ABSENT from the map —
/// `check_batch_windows` then reports the rule as uncheckable. Defaulting to
/// some plausible period is how a wrong window survives review.
fn batch_cadences() -> Result<std::collections::BTreeMap<&'static str, u64>> {
    let root = repo_root();
    let mut out = std::collections::BTreeMap::new();
    for batch in alert_conformance::BATCH_SERIES {
        let path = root.join(batch.manifest);
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let docs = YamlLoader::load_from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))?;
        let schedule = docs
            .iter()
            .find_map(|doc| doc["spec"]["schedule"].as_str())
            .with_context(|| {
                format!(
                    "{} declares no spec.schedule — BATCH_SERIES points at the wrong \
                     manifest",
                    path.display()
                )
            })?;
        if let Some(period) = alert_conformance::cron_period_secs(schedule) {
            out.insert(batch.prefix, period);
        } else {
            eprintln!(
                "warning: cannot classify schedule `{schedule}` in {}; rules reading \
                 `{}*` will be reported as uncheckable",
                path.display(),
                batch.prefix
            );
        }
    }
    Ok(out)
}

fn string_at(node: &Yaml, key: &str) -> String {
    node[key].as_str().unwrap_or_default().to_owned()
}

fn load(path: &PathBuf) -> Result<alert_conformance::RuleSet> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let docs = YamlLoader::load_from_str(&raw).context("parsing the rules YAML")?;
    let doc = docs.first().context("the rules file is empty")?;

    let groups = doc["groups"]
        .as_vec()
        .context("the rules file has no `groups` array")?;

    let mut set = alert_conformance::RuleSet {
        batch_cadences: batch_cadences()?,
        ..Default::default()
    };
    for group in groups {
        let group_name = string_at(group, "name");
        let rules = group["rules"]
            .as_vec()
            .with_context(|| format!("group `{group_name}` has no `rules` array"))?;
        for rule in rules {
            // Recording rules have no `alert:` and no severity; they are not
            // what these checks are about.
            let Some(name) = rule["alert"].as_str() else {
                continue;
            };
            // Parse the severity HERE, at the boundary, so an unroutable value
            // cannot exist downstream. A rule that fails to parse is carried as
            // `malformed` rather than aborting the load — one bad row must not
            // hide the findings in every other rule.
            match string_at(&rule["labels"], "severity").parse() {
                Ok(severity) => set.alerts.push(alert_conformance::Alert {
                    group: group_name.clone(),
                    name: name.to_owned(),
                    expr: string_at(rule, "expr"),
                    severity,
                    summary: string_at(&rule["annotations"], "summary"),
                    description: string_at(&rule["annotations"], "description"),
                }),
                Err(why) => set.malformed.push(format!("{name}: {why}")),
            }
        }
    }

    if set.alerts.is_empty() && set.malformed.is_empty() {
        bail!(
            "parsed 0 alerts out of {} — the file's shape changed and this test \
             would now pass vacuously",
            path.display()
        );
    }
    Ok(set)
}

#[test]
fn the_deployed_alert_rules_conform() -> Result<()> {
    let path = rules_path();
    let rules = load(&path)?;
    let violations = alert_conformance::violations(&rules);

    assert!(
        violations.is_empty(),
        "\n{} alert-rule violation(s) in {}:\n\n  - {}\n\n\
         These are rules that cannot fire, cannot route, or cannot be acted on. \
         See crates/alert-conformance/src/lib.rs for the reasoning behind each \
         check, and the header of the rules file for the threshold contract.\n",
        violations.len(),
        path.display(),
        violations.join("\n  - "),
    );
    Ok(())
}

/// A guard on the guard: if the parser silently stopped finding alerts, every
/// check above would pass on an empty set. Pin the shape loosely enough to
/// survive ordinary edits and tightly enough to catch that.
#[test]
fn the_parser_still_sees_the_whole_file() -> Result<()> {
    let rules = load(&rules_path())?;
    assert!(
        rules.alerts.len() > 30,
        "only {} alerts parsed — expected the full rule set",
        rules.alerts.len()
    );
    for required in [
        "FastPathLatencyHigh",
        "ScreeningLatencyP50High",
        "ScreeningLatencyP99High",
        "BackupAgentAbsent",
        "CopilotFabricatedCitations",
    ] {
        assert!(
            rules.alerts.iter().any(|a| a.name == required),
            "`{required}` is missing — either it was deleted, or the parser is \
             skipping a group"
        );
    }
    Ok(())
}

/// Every name in `telemetry::metrics::JOB_DURATION_METRICS` must actually be a
/// metric some crate exports.
///
/// This is the one remaining silent failure in the two-ladder design. The list
/// is matched with `Matcher::Full`, so a typo does not error, does not warn,
/// and does not fail to compile — the override simply never matches and the
/// metric stays quietly on the 10s latency ladder, which is precisely the
/// condition the second ladder was added to fix.
///
/// `telemetry` is a leaf crate and cannot depend on the services that declare
/// these constants, so this scans the source instead — the same move the
/// copilot prompt manifest makes with its `read_dir` sweep.
#[test]
fn every_job_duration_metric_name_is_one_a_crate_actually_exports() -> Result<()> {
    fn rust_sources(dir: &std::path::Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                rust_sources(&path, out)?;
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
        Ok(())
    }

    // Canonicalized, and that matters: `MANIFEST_DIR.join("..")` leaves
    // `alert-conformance` as a literal component of every path underneath it,
    // so the component filter below would exclude the entire corpus and this
    // test would fail for a reason that has nothing to do with the metric names.
    let crates_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .context("resolving crates/")?;
    let mut sources = Vec::new();
    rust_sources(&crates_dir, &mut sources).context("walking crates/")?;

    // Exclude `telemetry` (which declares the list as quoted string literals)
    // and this crate (whose sources quote both the list's name and, in this very
    // function, the guard string below). Either one in the corpus makes it match
    // itself and every assertion here pass vacuously — a test that cannot fail,
    // checking for rules that cannot fire. Neither crate exports a service
    // metric, so nothing is lost by skipping them.
    //
    // The guard that follows is not decoration: the first version of this test
    // excluded only `telemetry` and still passed vacuously, because
    // `tests/rules.rs` is itself inside `crates/`.
    const NOT_METRIC_PRODUCERS: [&str; 2] = ["telemetry", "alert-conformance"];
    let corpus = sources
        .iter()
        .filter(|p| {
            !p.components().any(|c| {
                NOT_METRIC_PRODUCERS
                    .iter()
                    .any(|skip| c.as_os_str() == *skip)
            })
        })
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect::<String>();
    assert!(
        !corpus.contains("JOB_DURATION_METRICS"),
        "the corpus contains the list this test reads, so it would match itself \
         and pass whatever the list said"
    );

    for metric in telemetry::metrics::JOB_DURATION_METRICS {
        let declaration = format!("\"{metric}\"");
        assert!(
            corpus.contains(&declaration),
            "`{metric}` is in telemetry::metrics::JOB_DURATION_METRICS but no crate \
             declares a metric by that name. A Matcher::Full override that matches \
             nothing fails silently: the metric keeps the 10s latency ladder and its \
             quantiles stay pinned at 10. Fix the spelling, or drop the entry."
        );
    }
    Ok(())
}
