//! The workspace's architectural seam rules, executable (§2 of
//! [engineering-conventions](../../../docs/engineering-conventions.md)).
//!
//! Every rule here is a dependency-direction decision the workspace already
//! made once, deliberately — recorded where review comments can't enforce it:
//! in a test that fails the build when a new crate takes a shortcut around a
//! seam. The rules are checked over the **direct** dependency edges of every
//! workspace member (`tests/workspace.rs` feeds them from `cargo metadata`),
//! so a violation names exactly the crate that drew the bad edge.
//!
//! When one of these fails you either (a) route through the seam the message
//! names, or (b) are consciously changing an architecture decision — do it in
//! this file, in the same PR, with the reasoning in the commit.

use std::collections::{BTreeMap, BTreeSet};

/// Workspace crate name → the names of its *direct* dependencies (workspace
/// and external alike, as declared in its `Cargo.toml`).
pub type DepGraph = BTreeMap<String, BTreeSet<String>>;

/// Run every seam rule; each violation is one human-readable sentence naming
/// the offending crate, the bad edge, and the seam to use instead. Empty means
/// conforming.
pub fn violations(graph: &DepGraph) -> Vec<String> {
    let mut out = Vec::new();
    let members: BTreeSet<&str> = graph.keys().map(String::as_str).collect();

    for (krate, deps) in graph {
        let has = |dep: &str| deps.contains(dep);

        // ── Detector plugins stay pure (the detector-api seam decision) ──
        // A detector is a pure plugin: it implements detector-api's trait and
        // reasons over the ctx it is handed. It never links the composing
        // service, a broker, or a store — that keeps every detector testable
        // with zero infrastructure and reusable by any composing binary.
        if krate.ends_with("-detector") {
            if !has("detector-api") {
                out.push(format!(
                    "{krate}: a *-detector crate must implement the detector-api seam \
                     (it has no detector-api dependency)"
                ));
            }
            for forbidden in [
                "detection",
                "event-bus",
                "rdkafka",
                "lapin",
                "sqlx",
                "redis",
                "clickhouse",
            ] {
                if has(forbidden) {
                    out.push(format!(
                        "{krate}: a detector crate must not depend on {forbidden} — \
                         detectors are pure plugins over detector-api; emission and \
                         storage are the composing service's job"
                    ));
                }
            }
        }

        // ── Only backtest composes the detection service crate ───────────
        // Everything else that wants detector vocabulary takes detector-api;
        // depending on `detection` couples a crate to the whole service.
        if has("detection") && krate != "backtest" {
            out.push(format!(
                "{krate}: depends on the `detection` service crate — depend on \
                 `detector-api` instead (only `backtest` replays through detection)"
            ));
        }

        // ── Kafka is never hand-rolled without the event-bus seam ─────────
        // rdkafka may appear for consumer plumbing, but always alongside
        // event-bus, so publishing goes through EventSink/publish_resilient
        // and consuming through run_consumer's Skip/DLQ/lag facilities.
        if has("rdkafka") && !has("event-bus") && krate != "event-bus" {
            out.push(format!(
                "{krate}: uses rdkafka without the event-bus seam — producers use \
                 EventSink/publish_resilient, consumers use run_consumer (Skip+DLQ, \
                 lag reporting); never raw rdkafka alone"
            ));
        }

        // ── The second broker exists at exactly one seam (§7) ─────────────
        // RabbitMQ carries SimulationJob commands and nothing else; a second
        // lapin consumer would be a second command channel the architecture
        // explicitly rejects.
        if has("lapin") && krate != "simulation" {
            out.push(format!(
                "{krate}: depends on lapin — RabbitMQ is the simulation work-queue \
                 seam only (§7); domain communication goes over the event bus"
            ));
        }

        // ── One metrics exporter, many facade call sites (§19) ────────────
        if has("metrics-exporter-prometheus") && krate != "telemetry" {
            out.push(format!(
                "{krate}: installs its own Prometheus exporter — record through the \
                 `metrics` facade and let telemetry::metrics::init own the recorder"
            ));
        }

        // ── Postgres access rides the shared db plumbing ──────────────────
        // Direct sqlx is fine for a crate's own store, but always alongside
        // `db` (connect + is_permanent classification) so retry/poison
        // decisions stay uniform.
        if has("sqlx") && !has("db") && krate != "db" {
            out.push(format!(
                "{krate}: uses sqlx without the shared `db` crate — pool connect and \
                 permanent-vs-transient error classification live there"
            ));
        }

        // ── Redis access rides the same shared db plumbing (§8/§9) ────────
        // The redis analog of the sqlx rule above: `db::redis::connect` +
        // `db::redis::is_transient` are the one place connection setup and
        // retry classification are decided, so a Redis-backed cache/store's
        // Transience impl can't drift from its siblings (this rule exists
        // because intelligence::cache and rule_engine::state_store both
        // hand-rolled byte-identical logic before `db::redis` existed).
        if has("redis") && !has("db") && krate != "db" {
            out.push(format!(
                "{krate}: uses redis without the shared `db` crate — connection setup \
                 and transient-vs-permanent error classification live in db::redis"
            ));
        }

        // ── ClickHouse access rides ch-migrate (§14) ──────────────────────
        // Every ClickHouse consumer applies its own migrations at boot via the
        // shared migrator (which also rejects the `?`-binding trap).
        if has("clickhouse") && !has("ch-migrate") && krate != "ch-migrate" {
            out.push(format!(
                "{krate}: uses the clickhouse client without ch-migrate — boot-time \
                 migrations + the `?`-literal guard are the shared discipline"
            ));
        }

        // ── The schema crate is the bottom of the graph (§2) ──────────────
        // `events` is pure data every service shares; a workspace dependency
        // from it would invert the whole graph. `detector-api` is the thin
        // detector contract: events only.
        if krate == "events" {
            let ws_deps: Vec<&str> = deps
                .iter()
                .map(String::as_str)
                .filter(|d| members.contains(d))
                .collect();
            if !ws_deps.is_empty() {
                out.push(format!(
                    "events: must have no workspace dependencies (found {ws_deps:?}) — \
                     the schema crate is the bottom of the dependency graph"
                ));
            }
        }
        if krate == "detector-api" {
            let extra: Vec<&str> = deps
                .iter()
                .map(String::as_str)
                .filter(|d| members.contains(d) && *d != "events")
                .collect();
            if !extra.is_empty() {
                out.push(format!(
                    "detector-api: may depend on `events` only (found {extra:?}) — \
                     the seam stays thin so detectors stay light"
                ));
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(edges: &[(&str, &[&str])]) -> DepGraph {
        edges
            .iter()
            .map(|(k, deps)| {
                (
                    (*k).to_owned(),
                    deps.iter().map(|d| (*d).to_owned()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn a_conforming_workspace_produces_no_violations() {
        let g = graph(&[
            ("events", &[]),
            ("detector-api", &["events"]),
            ("sandwich-detector", &["detector-api", "events"]),
            ("event-bus", &["events", "rdkafka", "metrics"]),
            ("detection", &["detector-api", "event-bus", "rdkafka"]),
            ("backtest", &["detection", "detector-api"]),
            ("telemetry", &["metrics-exporter-prometheus"]),
            ("db", &["sqlx", "redis"]),
            ("ch-migrate", &["clickhouse"]),
            (
                "simulation",
                &[
                    "lapin",
                    "event-bus",
                    "rdkafka",
                    "sqlx",
                    "db",
                    "clickhouse",
                    "ch-migrate",
                ],
            ),
            (
                "rule-engine",
                &["event-bus", "rdkafka", "sqlx", "db", "redis"],
            ),
        ]);
        assert_eq!(violations(&g), Vec::<String>::new());
    }

    #[test]
    fn each_rule_catches_its_shortcut() {
        let cases: &[(&str, &[&str], &str)] = &[
            (
                "evil-detector",
                &["detection", "detector-api"],
                "must not depend on detection",
            ),
            ("evil-detector", &["events"], "no detector-api dependency"),
            (
                "reporting",
                &["detection"],
                "depend on `detector-api` instead",
            ),
            ("reporting", &["rdkafka"], "without the event-bus seam"),
            ("reporting", &["lapin"], "simulation work-queue seam only"),
            (
                "reporting",
                &["metrics-exporter-prometheus"],
                "telemetry::metrics::init",
            ),
            ("reporting", &["sqlx"], "without the shared `db` crate"),
            ("reporting", &["redis"], "db::redis"),
            ("reporting", &["clickhouse"], "without ch-migrate"),
        ];
        for (krate, deps, expected) in cases {
            let g = graph(&[(*krate, *deps)]);
            let found = violations(&g);
            assert!(
                found.iter().any(|v| v.contains(expected)),
                "{krate} with {deps:?} should trip a rule mentioning {expected:?}, got {found:?}"
            );
        }
    }

    #[test]
    fn the_leaf_rules_hold_events_and_detector_api_at_the_bottom() {
        let g = graph(&[
            ("events", &["telemetry"]),
            ("detector-api", &["events", "event-bus"]),
            ("telemetry", &[]),
            ("event-bus", &["events"]),
        ]);
        let found = violations(&g);
        assert!(
            found
                .iter()
                .any(|v| v.contains("bottom of the dependency graph")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|v| v.contains("may depend on `events` only")),
            "{found:?}"
        );
    }
}
