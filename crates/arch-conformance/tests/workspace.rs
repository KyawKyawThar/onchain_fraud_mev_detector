//! The I/O shell: feed the real workspace's dependency graph (via
//! `cargo metadata`) through the pure seam rules in the lib. Runs under plain
//! `cargo test`/nextest, so a seam violation fails the same gate locally and
//! in CI — no extra tooling, no review vigilance required.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};

/// Workspace member → direct dependency names, from `cargo metadata --no-deps`
/// (declared edges only; no network, no lockfile resolution).
fn workspace_graph() -> Result<arch_conformance::DepGraph> {
    // The cargo that is running this test — respects toolchain pinning.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("running cargo metadata")?;
    anyhow::ensure!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("parsing cargo metadata JSON")?;
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata had no packages array")?;

    let mut graph: arch_conformance::DepGraph = BTreeMap::new();
    for package in packages {
        let name = package["name"]
            .as_str()
            .context("package without a name")?
            .to_owned();
        let deps: BTreeSet<String> = package["dependencies"]
            .as_array()
            .context("package without a dependencies array")?
            .iter()
            .filter_map(|d| d["name"].as_str().map(str::to_owned))
            .collect();
        graph.insert(name, deps);
    }
    anyhow::ensure!(!graph.is_empty(), "cargo metadata returned no packages");
    Ok(graph)
}

#[test]
fn the_workspace_dependency_graph_honors_the_seam_rules() -> Result<()> {
    let graph = workspace_graph()?;
    let violations = arch_conformance::violations(&graph);
    assert!(
        violations.is_empty(),
        "architectural seam violations (docs/engineering-conventions.md §2):\n  - {}",
        violations.join("\n  - ")
    );
    Ok(())
}
