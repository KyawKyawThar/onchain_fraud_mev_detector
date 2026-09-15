//! Shared by the deploy-tree conformance tests (`deploy_users.rs`,
//! `deploy_scaling.rs`): where the tree is and how to read it.

// Each test binary compiles this module and uses a subset of it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use yaml_rust2::{Yaml, YamlLoader};

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            yaml_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            out.push(path);
        }
    }
    Ok(())
}

/// Every YAML document under `deploy/k8s`, paired with its repo-relative path.
pub fn deploy_docs() -> Result<Vec<(String, Yaml)>> {
    let root = repo_root();
    let mut files = Vec::new();
    yaml_files(&root.join("deploy/k8s"), &mut files)?;
    files.sort();

    let mut docs = Vec::new();
    for path in &files {
        let raw = std::fs::read_to_string(path)?;
        let name = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        for doc in YamlLoader::load_from_str(&raw).with_context(|| format!("parsing {name}"))? {
            docs.push((name.clone(), doc));
        }
    }
    Ok(docs)
}

/// Parse one inline YAML document (unit-test fixtures).
pub fn yaml(src: &str) -> Yaml {
    YamlLoader::load_from_str(src)
        .expect("fixture parses")
        .remove(0)
}
