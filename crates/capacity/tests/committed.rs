//! The capacity gate, against the committed inputs.
//!
//! These run in the ordinary `cargo test`/nextest pass — no container, no
//! stack — so a change to the model, the event schema, the retention policy, a
//! crate's ClickHouse migrations or the deployed config re-judges the plan on
//! the PR that makes it.

use std::collections::BTreeSet;

use capacity::checks::{self, Finding, Severity};
use capacity::ddl::{self, TableDef};
use capacity::key::{Component, PartitionKey};
use capacity::model::Model;
use capacity::plan::{self, Inputs, Plan};
use capacity::units::Positive;
use capacity::{corpus, deploy_dir, report};
use events::DomainEvent;
use strum::VariantNames;

/// The readiness exit gate's margin over projected load.
const EXIT_GATE_HEADROOM: f64 = 1.5;

struct Fixture {
    model: Model,
    shapes: corpus::Shapes,
    tables: Vec<TableDef>,
    evidence_days: u32,
}

fn fixture() -> Fixture {
    Fixture {
        model: Model::load(&capacity::committed_model_path()).expect("committed model"),
        shapes: corpus::load(&capacity::default_corpus_dir()).expect("schema corpus"),
        tables: ddl::replay_workspace(&capacity::default_crates_dir()).expect("migrations"),
        evidence_days: retention::PolicySet::default().widest_evidence_days(),
    }
}

fn run(
    f: &Fixture,
    model: &Model,
    events_key: Option<&str>,
    evidence_days: u32,
    headroom: f64,
) -> (Plan, Vec<Finding>) {
    let inputs = Inputs {
        model,
        shapes: &f.shapes,
        tables: &f.tables,
        evidence_days,
        events_key_override: events_key.map(|k| PartitionKey::parse(k).unwrap()),
    };
    let plan = plan::plan(&inputs, Positive::new(headroom).unwrap()).expect("plan");
    let findings = checks::judge(model, &plan);
    (plan, findings)
}

fn breached(findings: &[Finding]) -> BTreeSet<&'static str> {
    findings
        .iter()
        .filter(|f| f.severity == Severity::Breach)
        .map(|f| f.check)
        .collect()
}

#[test]
fn the_committed_model_holds_at_the_exit_gate_headroom() {
    let f = fixture();
    let (plan, findings) = run(&f, &f.model, None, f.evidence_days, EXIT_GATE_HEADROOM);
    assert!(
        !checks::has_breach(&findings),
        "{}",
        report::render(&plan, &f.model, &findings)
    );
}

/// A new event type cannot ship unpriced, and a renamed one cannot leave a
/// stale rate behind.
#[test]
fn every_domain_event_is_priced_and_nothing_else_is() {
    let model = fixture().model;
    let priced: BTreeSet<&str> = model.events.keys().map(String::as_str).collect();
    let schema: BTreeSet<&str> = DomainEvent::VARIANTS.iter().copied().collect();
    let unpriced: Vec<_> = schema.difference(&priced).collect();
    let stale: Vec<_> = priced.difference(&schema).collect();
    assert!(
        unpriced.is_empty(),
        "DomainEvent variants with no rate in crates/capacity/model.json: {unpriced:?}"
    );
    assert!(
        stale.is_empty(),
        "rates for no DomainEvent variant: {stale:?}"
    );
}

#[test]
fn every_domain_event_has_a_measured_size() {
    let shapes = fixture().shapes;
    let missing: Vec<_> = DomainEvent::VARIANTS
        .iter()
        .filter(|v| !shapes.contains_key(**v))
        .collect();
    assert!(
        missing.is_empty(),
        "no schema corpus fixture for {missing:?}"
    );
}

/// Every ClickHouse table any crate migrates is replayed and priced — and the
/// two the capacity plan changed come out with their new keys, while no staged
/// or retired name leaks into the gate.
#[test]
fn every_clickhouse_table_in_the_workspace_is_priced() {
    let f = fixture();
    let find = |id: &str| {
        f.tables
            .iter()
            .find(|t| t.id() == id)
            .unwrap_or_else(|| panic!("{id} not replayed from the migrations"))
    };
    let events = find("event-store/events");
    assert!(events.key.has(Component::Month) && !events.key.has(Component::EventType));
    assert_eq!(events.engine, "ReplacingMergeTree");
    let analytics = find("simulation/incident_analytics");
    assert!(analytics.key.has(Component::Month) && !analytics.key.has(Component::Day));
    assert!(
        f.tables.len() >= 8,
        "expected every crate's tables: {:#?}",
        f.tables
    );
    for table in &f.tables {
        assert!(
            !table.name.ends_with(ddl::STAGED_SUFFIX) && !table.name.ends_with(ddl::RETIRED_SUFFIX),
            "{} leaked through the swap convention",
            table.id()
        );
    }
}

/// The gate can fail, and on the exact key it was written for.
#[test]
fn the_gate_fails_the_original_daily_key() {
    let f = fixture();
    let (plan, findings) = run(
        &f,
        &f.model,
        Some("(chain, event_type, toDate(occurred_at))"),
        f.evidence_days,
        1.0,
    );
    let got = breached(&findings);
    for check in [
        "clickhouse.max_parts_in_total",
        "clickhouse.max_partitions_per_insert_block",
        "clickhouse.partition_budget",
    ] {
        assert!(got.contains(check), "expected a {check} breach: {got:?}");
    }
    let events = plan
        .tables
        .iter()
        .find(|t| t.id == "event-store/events")
        .unwrap();
    let day = events.parts_limit_day.expect("the parts limit is reached");
    assert!(day < f.evidence_days, "day {day} must be inside the window");
}

/// A ten-year policy (the EU member-state maximum) is past what the monthly key
/// keeps under the insert-block limit — the advisory's claim, held to account.
#[test]
fn a_ten_year_window_breaches_the_monthly_key() {
    let f = fixture();
    let (_, findings) = run(&f, &f.model, None, 3653, 1.0);
    assert!(breached(&findings).contains("clickhouse.max_partitions_per_insert_block"));
}

/// One insert per event was the ingest before batching; at the horizon's peak it
/// out-inserts ClickHouse's merges by orders of magnitude.
#[test]
fn per_record_ingest_breaches_the_insert_rate() {
    let f = fixture();
    let mut model = f.model.clone();
    model.ingest.batch_max_rows = 1;
    let (plan, findings) = run(&f, &model, None, f.evidence_days, 1.0);
    assert!(breached(&findings).contains("event-store.inserts_per_second"));
    assert!(
        plan.inserts.inserts_per_second > 100.0,
        "{:?}",
        plan.inserts
    );
}

/// A shard key that sends copies of one event to different shards defeats the
/// engine's deduplication; one that shards by chain builds a hot shard.
#[test]
fn a_shard_key_that_splits_duplicates_is_refused() {
    let f = fixture();
    for key in ["rand()", "chain", "cityHash64(event_id, chain)"] {
        let mut model = f.model.clone();
        model.clickhouse.shard_key = key.into();
        let (_, findings) = run(&f, &model, None, f.evidence_days, 1.0);
        assert!(
            breached(&findings).contains("clickhouse.shard_key"),
            "{key}"
        );
    }
}

/// With no growth the store plateaus at exactly one window of volume.
#[test]
fn without_growth_the_store_plateaus_at_one_window() {
    let f = fixture();
    let model = f.model.clone().with_growth(Positive::new(1.0).unwrap());
    let (plan, _) = run(&f, &model, None, f.evidence_days, 1.0);
    let last = plan.years.last().unwrap().stored_gib;
    let expected = plan.day_one.stored_gib_per_day * f64::from(plan.window_days);
    assert!(
        ((last - expected) / expected).abs() < 1e-9,
        "{last} vs {expected}"
    );
}

#[test]
fn known_chains_do_not_share_a_partition_at_the_deployed_count() {
    let f = fixture();
    let (plan, _) = run(&f, &f.model, None, f.evidence_days, 1.0);
    assert_eq!(
        plan.kafka.chain_parallelism as usize,
        f.model.chains.len(),
        "{:?}",
        plan.kafka.chain_partitions
    );
}

/// The model's `deployed_*` and ingest fields describe the manifests, not a
/// hope: a gate that judged a different config from the deployed one would pass
/// what the deployment fails.
#[test]
fn the_model_is_pinned_to_the_deployed_manifests() {
    let model = fixture().model;
    let base = deploy_dir().join("k8s/base");
    let read = |p: &str| std::fs::read_to_string(base.join(p)).expect(p);
    let app_config = read("app-config.yaml");

    assert_eq!(
        yaml_value(&app_config, "KAFKA_TOPIC_PARTITIONS:")
            .parse::<u32>()
            .unwrap(),
        model.kafka.deployed_partitions
    );
    assert_eq!(
        yaml_value(&app_config, "EVENT_STORE_BATCH_MAX_ROWS:")
            .parse::<u64>()
            .unwrap(),
        model.ingest.batch_max_rows
    );
    assert_eq!(
        yaml_value(&app_config, "EVENT_STORE_BATCH_MAX_WAIT_MS:")
            .parse::<u64>()
            .unwrap(),
        model.ingest.batch_max_wait_ms
    );
    assert_eq!(
        gib(&yaml_value(&read("infra/clickhouse.yaml"), "storage:")),
        model.clickhouse.deployed_pvc_gib.get()
    );
    assert_eq!(
        gib(&yaml_value(&read("infra/kafka.yaml"), "storage:")),
        model.kafka.deployed_pvc_gib.get()
    );
}

/// `EventStoreGrowthAboveCapacityPlan` fires on the plan's own number. Editing
/// the model without re-pinning the alert, or the alert without the model, fails
/// here — a threshold with provenance (§19b), not a number someone typed.
#[test]
fn the_drift_alert_is_pinned_to_the_plan() {
    let f = fixture();
    let (plan, _) = run(&f, &f.model, None, f.evidence_days, 1.0);
    let rules = std::fs::read_to_string(deploy_dir().join("prometheus-rules.yml")).unwrap();
    let after = rules
        .split("alert: EventStoreGrowthAboveCapacityPlan")
        .nth(1)
        .expect("EventStoreGrowthAboveCapacityPlan is declared");
    let expr = after
        .lines()
        .find_map(|l| l.trim().strip_prefix("expr:"))
        .expect("the alert has an expr");
    let threshold: u64 = expr
        .rsplit('>')
        .next()
        .unwrap()
        .trim()
        .parse()
        .expect("a numeric threshold");
    assert_eq!(
        threshold, plan.drift_ceiling_payload_bytes_per_day,
        "re-pin deploy/prometheus-rules.yml to the value `just capacity-plan` prints"
    );
}

/// The value of the last line carrying `key`, unquoted.
fn yaml_value(yaml: &str, key: &str) -> String {
    yaml.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once(key).map(|(_, v)| v))
        .next_back()
        .unwrap_or_else(|| panic!("{key} not found"))
        .trim()
        .trim_matches('"')
        .to_owned()
}

fn gib(quantity: &str) -> f64 {
    quantity
        .strip_suffix("Gi")
        .unwrap_or_else(|| panic!("expected a Gi quantity, got {quantity}"))
        .parse()
        .expect("Gi quantity")
}
