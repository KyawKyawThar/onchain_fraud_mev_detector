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
                // The crate that owns labels, entities and risk scores. A
                // detector names *behaviour*, never an actor (§6) — and the
                // ctx it is handed physically carries no labels, so an edge
                // here could only exist to reach around that.
                "intelligence",
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

            // ── An ML detector executes its model behind the seam (§20.2) ──
            // `inference` is where a runtime lives, which is what keeps a
            // detector's logic — thresholds, evidence, top contributing
            // features — testable with no native library in the test binary,
            // and what keeps the *serving* side attribution-blind (the seam
            // scores a `FeatureVector`, never a `DetectionCtx`). A detector
            // holding `ort` directly would give all of that back.
            if has("ort") {
                out.push(format!(
                    "{krate}: a detector crate must not depend on ort — a model is \
                     executed behind the `inference` seam (§20.2), so the detector's \
                     logic stays testable without an ONNX Runtime and cannot see \
                     anything but a feature vector"
                ));
            }
        }

        // ── Feature extraction is held to detector purity (§20.1) ─────────
        // ml-features turns the DetectionCtx into training/serving vectors,
        // so it obeys the same rules as the detectors that consume them:
        // detector-api only, no service/broker/store edges — and above all no
        // `intelligence`, whose labels would silently turn "attribution-blind
        // features" into a list of known actors in disguise.
        if krate == "ml-features" {
            if !has("detector-api") {
                out.push(format!(
                    "{krate}: must extract from the detector-api seam \
                     (it has no detector-api dependency)"
                ));
            }
            for forbidden in [
                "detection",
                "intelligence",
                "event-bus",
                "rdkafka",
                "lapin",
                "sqlx",
                "redis",
                "clickhouse",
            ] {
                if has(forbidden) {
                    out.push(format!(
                        "{krate}: must not depend on {forbidden} — feature extraction \
                         is a pure, attribution-blind function of the DetectionCtx \
                         (§20.1); export/serving plumbing lives in the composing \
                         binaries"
                    ));
                }
            }
        }

        // ── Training data inherits attribution-blindness (§20.1) ──────────
        // The dataset exporter materialises what an ML detector will learn
        // from, so the §6 rule has to hold one step *upstream* of the
        // detector: if a training row could carry a label or an attribution,
        // the model becomes a list of known actors no matter how blind the
        // serving path is. It gets its features from `ml-features` (which is
        // itself held to detector purity above) and never from a store, and
        // `intelligence` — the crate that owns labels, entities and risk
        // scores — must not be on its edge at all.
        if krate == "dataset" {
            if !has("ml-features") {
                out.push(format!(
                    "{krate}: must build feature vectors through the `ml-features` seam \
                     (it has no ml-features dependency) — the training/serving contract \
                     is that crate's versioned schema, not a local extraction"
                ));
            }
            for forbidden in ["intelligence", "detection", "sqlx", "redis"] {
                if has(forbidden) {
                    out.push(format!(
                        "{krate}: must not depend on {forbidden} — training data obeys the \
                         same attribution-blindness as the detectors that consume it \
                         (§20.1); a labeled row is a replayed event plus an ml-features \
                         vector, nothing else"
                    ));
                }
            }
        }

        // ── Model serving is held to the same purity (§20.2) ─────────────
        // `inference` is the seam a model is executed behind. It scores a
        // `FeatureVector` and nothing else, which is what keeps the *serving*
        // side attribution-blind by construction (§6) — an engine that could
        // reach `intelligence` would undo everything `ml-features` guarantees
        // upstream of it. It also stays off the service/broker/store edges so
        // a detector crate can link it without dragging a runtime's worth of
        // infrastructure into its tests.
        if krate == "inference" {
            if !has("ml-features") {
                out.push(format!(
                    "{krate}: must serve the `ml-features` contract (it has no ml-features \
                     dependency) — the training/serving boundary is that crate's versioned \
                     schema plus the ONNX artifact, nothing else"
                ));
            }
            for forbidden in [
                "detection",
                "intelligence",
                "event-bus",
                "rdkafka",
                "lapin",
                "sqlx",
                "redis",
                "clickhouse",
            ] {
                if has(forbidden) {
                    out.push(format!(
                        "{krate}: must not depend on {forbidden} — model serving is a pure \
                         function of a FeatureVector (§20.2); a model that could see anything \
                         else would not be attribution-blind"
                    ));
                }
            }
        }

        // ── The shared resilience primitives stay primitive (§5, §20.4) ──
        // `resilience` holds the circuit breaker and the retry/backoff policy
        // that guard *every* call to something outside this system — an RPC
        // endpoint, a model provider, and whatever comes next. It is a leaf,
        // like `events`: pure state machines with the clock passed in, no I/O,
        // no runtime. The moment it grows a workspace edge it stops being
        // linkable from anywhere, and the copy-paste it was promoted to
        // prevent comes straight back.
        if krate == "resilience" {
            let ws_deps: Vec<&str> = deps
                .iter()
                .map(String::as_str)
                .filter(|d| members.contains(d))
                .collect();
            if !ws_deps.is_empty() {
                out.push(format!(
                    "resilience: must have no workspace dependencies (found {ws_deps:?}) — \
                     the shared breaker/backoff primitives are a leaf so anything can \
                     link them without inheriting a runtime"
                ));
            }
        }

        // ── Auth is verified in one place (§11) ─────────────────────────
        // `auth` holds the JWT verification every service that authenticates a
        // caller shares — signature, expiry, issuer, claims. A leaf like
        // `resilience`, for the same reason: it must be linkable from a
        // service without dragging a runtime in, and a second copy of "is this
        // token real" is a second answer to a question that must have one.
        //
        // It also must never gain issuance. A library that can both mint and
        // verify invites a service to trust a token it minted for itself,
        // which is not authentication.
        if krate == "auth" {
            let ws_deps: Vec<&str> = deps
                .iter()
                .map(String::as_str)
                .filter(|d| members.contains(d))
                .collect();
            if !ws_deps.is_empty() {
                out.push(format!(
                    "auth: must have no workspace dependencies (found {ws_deps:?}) — \
                     shared bearer verification is a leaf so any service can link it"
                ));
            }
        }

        // ── The LLM seam stays a seam (§20.4) ────────────────────────────
        // `llm` owns transport, retry policy and token accounting, and
        // nothing else. Two directions matter:
        //
        // * it meters through `event-bus` (`UsageFact` over `EventSink`) — an
        //   LLM-shaped second metering path would be a billing SKU nobody can
        //   reconcile (§13), which is the same reason no producer hand-rolls
        //   rdkafka;
        // * it must not reach a store or a domain service. A seam that could
        //   read the graph, the rule store, or `intelligence` would make "LLM
        //   output is a proposal, never a fact" a convention instead of a
        //   structural property: the copilot's safety argument rests on a
        //   draft having to pass a validating boundary (the rule parser, a
        //   human approval) that lives *above* this crate.
        if krate == "llm" {
            if !has("event-bus") {
                out.push(format!(
                    "{krate}: must meter token usage through the event-bus seam \
                     (it has no event-bus dependency) — `UsageRecorded` has one \
                     producer path (§13), not an LLM-specific one"
                ));
            }
            for forbidden in [
                "intelligence",
                "rule-engine",
                "simulation",
                "sqlx",
                "redis",
                "clickhouse",
                "rdkafka",
                "lapin",
            ] {
                if has(forbidden) {
                    out.push(format!(
                        "{krate}: must not depend on {forbidden} — the LLM seam owns \
                         transport, retry and token accounting only (§20.4); reading \
                         the audit stream, compiling a drafted rule and storing an \
                         approval are the copilot service's job, above this seam"
                    ));
                }
            }
        }

        // ── The copilot reads other services over their APIs (§20.4/§14) ──
        // The copilot's whole safety argument is that a draft must cross a
        // validating boundary before anything acts on it. That argument only
        // holds while the boundaries are *other services'*:
        //
        // * it must go through the `llm` seam, never a hand-rolled HTTP call
        //   to a provider — that is where metering, retry, admission and the
        //   response cache live, and a second path around them is an
        //   unreconcilable billing SKU (§13);
        // * it reads the incident's audit stream over event-store's HTTP read
        //   API, so no `clickhouse` and no `event-store` edge: a service that
        //   could query another's store is the cross-service join §14 forbids,
        //   and it would couple a draft to a schema it does not own.
        //
        // `rule-engine` is deliberately *absent* from this list: t4 compiles a
        // drafted rule through that crate's existing parse boundary, which is
        // the hallucination-safety mechanism, not a shortcut around one.
        if krate == "copilot" {
            if !has("llm") {
                out.push(format!(
                    "{krate}: must reach the model through the `llm` seam \
                     (it has no llm dependency) — transport, retry, admission, \
                     metering and the response cache live there (§20.4)"
                ));
            }
            for forbidden in ["clickhouse", "event-store", "intelligence", "detection"] {
                if has(forbidden) {
                    out.push(format!(
                        "{krate}: must not depend on {forbidden} — the copilot reads \
                         other services over their APIs (§14: no cross-service joins, \
                         no shared tables); its own store is `copilot_drafts` alone"
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
            (
                "anomaly-detector",
                &["detector-api", "events", "ml-features", "inference", "sha2"],
            ),
            ("ml-features", &["detector-api", "serde", "sha2"]),
            ("event-bus", &["events", "rdkafka", "metrics"]),
            ("detection", &["detector-api", "event-bus", "rdkafka"]),
            ("backtest", &["detection", "detector-api"]),
            (
                "dataset",
                &[
                    "ml-features",
                    "detector-api",
                    "events",
                    "clickhouse",
                    "ch-migrate",
                ],
            ),
            (
                "inference",
                &["ml-features", "detector-api", "ort", "metrics"],
            ),
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
            (
                "llm",
                &[
                    "events",
                    "event-bus",
                    "telemetry",
                    "resilience",
                    "bounded-map",
                    "reqwest",
                ],
            ),
            (
                "copilot",
                &[
                    "events",
                    "llm",
                    "event-bus",
                    "rdkafka",
                    "sqlx",
                    "db",
                    "reqwest",
                    "telemetry",
                ],
            ),
            ("resilience", &[]),
            ("ingestion", &["event-bus", "rdkafka", "resilience"]),
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
                "evil-detector",
                &["detector-api", "intelligence"],
                "must not depend on intelligence",
            ),
            (
                "evil-detector",
                &["detector-api", "ml-features", "ort"],
                "executed behind the `inference` seam",
            ),
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
            ("ml-features", &["events"], "no detector-api dependency"),
            (
                "ml-features",
                &["detector-api", "intelligence"],
                "attribution-blind function of the DetectionCtx",
            ),
            (
                "dataset",
                &["ml-features", "intelligence", "clickhouse", "ch-migrate"],
                "training data obeys the same attribution-blindness",
            ),
            (
                "dataset",
                &["events", "clickhouse", "ch-migrate"],
                "no ml-features dependency",
            ),
            (
                "inference",
                &["ml-features", "intelligence"],
                "model serving is a pure function of a FeatureVector",
            ),
            ("inference", &["ort"], "no ml-features dependency"),
            ("llm", &["events", "reqwest"], "no event-bus dependency"),
            (
                "llm",
                &["event-bus", "intelligence"],
                "owns transport, retry and token accounting only",
            ),
            (
                "llm",
                &["event-bus", "rule-engine"],
                "compiling a drafted rule",
            ),
            (
                "copilot",
                &["events", "event-bus", "rdkafka", "sqlx", "db", "reqwest"],
                "no llm dependency",
            ),
            (
                "copilot",
                &[
                    "llm",
                    "event-bus",
                    "rdkafka",
                    "sqlx",
                    "db",
                    "clickhouse",
                    "ch-migrate",
                ],
                "no cross-service joins",
            ),
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
            ("resilience", &["events"]),
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
        assert!(
            found
                .iter()
                .any(|v| v.contains("resilience: must have no workspace dependencies")),
            "{found:?}"
        );
    }
}
