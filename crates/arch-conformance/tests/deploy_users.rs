//! Containers run as a NUMERIC non-root user, checked against the deploy tree.
//!
//! Every pod in `deploy/k8s` sets `runAsNonRoot: true`, and the kubelet can only
//! honour that against a numeric uid. An image whose user is a *name*
//! (`appuser`, `nobody`) in a pod that does not set `runAsUser` gets
//! `CreateContainerConfigError: image has non-numeric user ... cannot verify
//! user is non-root`, and the container never starts. Until 2026-09-14 that was
//! every service built from `deploy/Dockerfile`, plus Prometheus and
//! Alertmanager, and only running the tree on kind found it. Nothing earlier
//! fails: the images build, the overlays render, kubeconform validates.
//!
//! Two rules close it:
//!
//! 1. Every `USER` in our Dockerfiles is numeric. `root` is allowed only as a
//!    temporary switch; the last `USER` must be numeric.
//! 2. A container under `runAsNonRoot` that runs a THIRD-PARTY image has a
//!    `runAsUser`, at pod or container level. What user a pulled image declares
//!    cannot be seen without pulling it, so the manifest has to state it. Our
//!    own images are covered by rule 1 instead.

mod common;

use anyhow::{Context, Result};
use yaml_rust2::Yaml;

/// Images built from this repository's Dockerfiles (rule 1 covers them).
const OUR_IMAGES: &str = "ghcr.io/kyawkyawthar/onchain_fraud_mev_detector/";

const DOCKERFILES: &[&str] = &["deploy/Dockerfile", "deploy/models/Dockerfile"];

/// `10001` or `10001:10001`.
fn is_numeric_user(spec: &str) -> bool {
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    match spec.split_once(':') {
        Some((uid, gid)) => digits(uid) && digits(gid),
        None => digits(spec),
    }
}

/// Numeric and not uid 0: `USER 0` / `runAsUser: 0` is root, which the kubelet
/// refuses under `runAsNonRoot` at container start, the same late failure.
fn is_non_root_numeric_user(spec: &str) -> bool {
    is_numeric_user(spec)
        && spec
            .split(':')
            .next()
            .is_some_and(|uid| uid.bytes().any(|b| b != b'0'))
}

/// Rule 1 over one Dockerfile's text.
fn dockerfile_violations(name: &str, text: &str) -> Vec<String> {
    let users: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("USER "))
        .map(str::trim)
        .collect();
    let mut out: Vec<String> = users
        .iter()
        .filter(|u| **u != "root" && !is_numeric_user(u))
        .map(|u| format!("{name}: `USER {u}` is a name, not a numeric uid[:gid]"))
        .collect();
    if let Some(last) = users.last() {
        if !is_non_root_numeric_user(last) {
            out.push(format!(
                "{name}: the final `USER {last}` is not a numeric non-root user"
            ));
        }
    }
    out
}

/// Every mapping with a `containers` list: a pod spec, wherever it sits
/// (Deployment, StatefulSet, CronJob's job template, a component patch).
fn pod_specs<'a>(node: &'a Yaml, out: &mut Vec<&'a Yaml>) {
    match node {
        Yaml::Hash(map) => {
            if node["containers"].as_vec().is_some() {
                out.push(node);
            }
            for value in map.values() {
                pod_specs(value, out);
            }
        }
        Yaml::Array(items) => items.iter().for_each(|v| pod_specs(v, out)),
        _ => {}
    }
}

/// Rule 2 over one pod spec.
fn pod_violations(file: &str, pod: &Yaml) -> Vec<String> {
    let pod_ctx = &pod["securityContext"];
    let mut out = Vec::new();
    for key in ["initContainers", "containers"] {
        for container in pod[key].as_vec().into_iter().flatten() {
            let ctx = &container["securityContext"];
            let non_root = ctx["runAsNonRoot"]
                .as_bool()
                .or_else(|| pod_ctx["runAsNonRoot"].as_bool())
                .unwrap_or(false);
            let image = container["image"].as_str().unwrap_or_default();
            if !non_root || image.starts_with(OUR_IMAGES) {
                continue;
            }
            let uid = ctx["runAsUser"]
                .as_i64()
                .or_else(|| pod_ctx["runAsUser"].as_i64());
            let has_uid = uid.is_some_and(|u| u > 0);
            if !has_uid {
                out.push(format!(
                    "{file}: container `{}` runs third-party image `{image}` under \
                     runAsNonRoot with no non-zero runAsUser. If the image's user is a name, \
                     the kubelet refuses to start it. Set the image's numeric uid \
                     explicitly (`docker image inspect -f '{{{{.Config.User}}}}'`, \
                     then `id` inside it).",
                    container["name"].as_str().unwrap_or("?")
                ));
            }
        }
    }
    out
}

#[test]
fn our_dockerfiles_switch_to_a_numeric_user() -> Result<()> {
    let mut violations = Vec::new();
    for name in DOCKERFILES {
        let text = std::fs::read_to_string(common::repo_root().join(name))
            .with_context(|| format!("reading {name}"))?;
        anyhow::ensure!(
            text.lines().any(|l| l.trim().starts_with("USER ")),
            "{name} has no USER instruction at all; it would run as root"
        );
        violations.extend(dockerfile_violations(name, &text));
    }
    assert!(
        violations.is_empty(),
        "\n  - {}\n",
        violations.join("\n  - ")
    );
    Ok(())
}

#[test]
fn third_party_images_under_run_as_non_root_declare_their_uid() -> Result<()> {
    let mut pods = 0;
    let mut violations = Vec::new();
    for (name, doc) in common::deploy_docs()? {
        let mut specs = Vec::new();
        pod_specs(&doc, &mut specs);
        pods += specs.len();
        for pod in specs {
            violations.extend(pod_violations(&name, pod));
        }
    }

    // A guard on the guard: a walk that silently found nothing would pass.
    assert!(pods > 20, "only {pods} pod specs found under deploy/k8s");
    assert!(
        violations.is_empty(),
        "\n  - {}\n",
        violations.join("\n  - ")
    );
    Ok(())
}

#[test]
fn numeric_users_are_recognised_and_names_are_not() {
    for ok in ["10001", "10001:10001", "65534:65534", "0"] {
        assert!(is_numeric_user(ok), "{ok}");
    }
    for bad in ["appuser", "nobody", "10001:appuser", ":10001", "10001:", ""] {
        assert!(!is_numeric_user(bad), "{bad}");
    }
}

#[test]
fn the_shipped_dockerfile_bug_is_caught() {
    let before = "FROM debian\nRUN useradd -r -u 10001 appuser\nUSER appuser\n";
    assert_eq!(dockerfile_violations("Dockerfile", before).len(), 2);

    // Numeric but root: the final user must be non-root, not merely a number.
    assert_eq!(
        dockerfile_violations("Dockerfile", "FROM x\nUSER 0:0\n").len(),
        1
    );

    // A temporary root switch is fine as long as the image ends numeric.
    let after =
        "FROM x\nUSER 10001:10001\nFROM y\nUSER root\nRUN apt-get update\nUSER 10001:10001\n";
    assert!(dockerfile_violations("Dockerfile", after).is_empty());
}

#[test]
fn the_shipped_prometheus_pod_is_caught_and_the_fix_passes() {
    let pod = |uid: &str| {
        common::yaml(&format!(
            "spec:\n  template:\n    spec:\n      securityContext:\n        runAsNonRoot: true\n{uid}      containers:\n        - name: prometheus\n          image: prom/prometheus:latest\n        - name: ours\n          image: {OUR_IMAGES}server:latest\n"
        ))
    };
    let check = |doc: &Yaml| {
        let mut specs = Vec::new();
        pod_specs(doc, &mut specs);
        specs
            .iter()
            .flat_map(|p| pod_violations("x.yaml", p))
            .collect::<Vec<_>>()
    };

    let broken = check(&pod(""));
    assert_eq!(
        broken.len(),
        1,
        "only the third-party container: {broken:?}"
    );
    assert!(broken[0].contains("prom/prometheus"));

    assert!(check(&pod("        runAsUser: 65534\n")).is_empty());
    assert_eq!(
        check(&pod("        runAsUser: 0\n")).len(),
        1,
        "runAsUser 0 is root"
    );
}
