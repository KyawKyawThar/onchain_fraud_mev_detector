//! Scaling shape, checked against the deploy tree.
//!
//! The K8s README's per-service table states the rule: an HPA only where
//! replicas are interchangeable, and nothing else competing with it for the
//! replica count. This makes the rule fail a build. For every
//! HorizontalPodAutoscaler under `deploy/k8s`:
//!
//! 1. **Its target exists.** A mistyped `scaleTargetRef` is an HPA that scales
//!    nothing, and the only place that says so is `kubectl describe hpa`.
//! 2. **The target is not `strategy: Recreate`.** Recreate is how this tree marks
//!    a single writer (detection per chain, rule-engine,
//!    intelligence-attribute). There, a second replica either idles behind a
//!    partition or corrupts state it assumes it owns alone.
//! 3. **The target does not set `spec.replicas`.** With an HPA, every
//!    `kubectl apply` re-applies that literal and resets a scaled-out pool. That
//!    is most likely mid-incident, because that is when people deploy.

mod common;

use anyhow::Result;
use yaml_rust2::Yaml;

fn str_at<'a>(node: &'a Yaml, path: &[&str]) -> Option<&'a str> {
    path.iter().fold(node, |n, key| &n[*key]).as_str()
}

fn violations(docs: &[(String, Yaml)]) -> Vec<String> {
    let mut out = Vec::new();
    let hpas = docs
        .iter()
        .filter(|(_, d)| str_at(d, &["kind"]) == Some("HorizontalPodAutoscaler"));
    for (file, hpa) in hpas {
        let hpa_name = str_at(hpa, &["metadata", "name"]).unwrap_or("?");
        let kind = str_at(hpa, &["spec", "scaleTargetRef", "kind"]).unwrap_or("?");
        let name = str_at(hpa, &["spec", "scaleTargetRef", "name"]).unwrap_or("?");

        let target = docs.iter().find(|(_, d)| {
            str_at(d, &["kind"]) == Some(kind) && str_at(d, &["metadata", "name"]) == Some(name)
        });
        let Some((target_file, workload)) = target else {
            out.push(format!(
                "{file}: HPA `{hpa_name}` targets {kind} `{name}`, which nothing under deploy/k8s defines"
            ));
            continue;
        };

        if str_at(workload, &["spec", "strategy", "type"]) == Some("Recreate") {
            out.push(format!(
                "{target_file}: {kind} `{name}` is `strategy: Recreate` (this tree's mark of a \
                 single writer) but HPA `{hpa_name}` scales it. Either it is interchangeable and \
                 should roll, or it is a single writer and must not be autoscaled."
            ));
        }
        if !workload["spec"]["replicas"].is_badvalue() {
            out.push(format!(
                "{target_file}: {kind} `{name}` sets spec.replicas while HPA `{hpa_name}` owns the \
                 count. Every `kubectl apply` would reset a scaled-out pool to that literal. \
                 Remove it; the HPA's minReplicas is the floor."
            ));
        }
    }
    out
}

#[test]
fn every_autoscaled_workload_is_interchangeable_and_hpa_owned() -> Result<()> {
    let docs = common::deploy_docs()?;
    let hpas = docs
        .iter()
        .filter(|(_, d)| str_at(d, &["kind"]) == Some("HorizontalPodAutoscaler"))
        .count();
    // A guard on the guard: a walk that silently found no HPAs would pass.
    assert!(hpas >= 3, "only {hpas} HPAs found under deploy/k8s");

    let found = violations(&docs);
    assert!(found.is_empty(), "\n  - {}\n", found.join("\n  - "));
    Ok(())
}

fn fixture(workload: &str) -> Vec<(String, Yaml)> {
    let hpa = "kind: HorizontalPodAutoscaler\nmetadata: {name: w}\nspec:\n  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: w}\n";
    vec![
        ("hpa.yaml".into(), common::yaml(hpa)),
        ("w.yaml".into(), common::yaml(workload)),
    ]
}

#[test]
fn a_conforming_target_passes() {
    let docs = fixture("kind: Deployment\nmetadata: {name: w}\nspec:\n  selector: {}\n");
    assert!(violations(&docs).is_empty());
}

#[test]
fn a_hard_coded_replica_count_under_an_hpa_is_caught() {
    let docs = fixture("kind: Deployment\nmetadata: {name: w}\nspec:\n  replicas: 2\n");
    let found = violations(&docs);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("spec.replicas"));
}

#[test]
fn an_autoscaled_single_writer_is_caught() {
    let docs =
        fixture("kind: Deployment\nmetadata: {name: w}\nspec:\n  strategy: {type: Recreate}\n");
    let found = violations(&docs);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("Recreate"));
}

#[test]
fn a_dangling_target_is_caught() {
    let docs = fixture("kind: Deployment\nmetadata: {name: someone-else}\nspec: {}\n");
    let found = violations(&docs);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("nothing under deploy/k8s defines"));
}
