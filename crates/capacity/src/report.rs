//! The plan as text: what a red job and a planning review are both read by.

use std::fmt::Write;

use crate::checks::{Finding, Severity};
use crate::model::Model;
use crate::plan::{Plan, Window};

pub fn render(plan: &Plan, model: &Model, findings: &[Finding]) -> String {
    let mut s = String::new();
    // Writing to a String cannot fail.
    let _ = write_report(&mut s, plan, model, findings);
    s
}

fn write_report(
    s: &mut String,
    plan: &Plan,
    model: &Model,
    findings: &[Finding],
) -> std::fmt::Result {
    writeln!(
        s,
        "capacity plan — {} at {}× headroom",
        plan.model, plan.headroom
    )?;
    writeln!(
        s,
        "evidence window {} days (+{} expiry lag) · events PARTITION BY {} · horizon {} years at {}×/year",
        plan.evidence_days,
        plan.window_days - plan.evidence_days,
        plan.events_key,
        model.horizon_years,
        model.annual_growth.get()
    )?;
    writeln!(s)?;
    writeln!(
        s,
        "day one: {} events/day · {} stored/day (one replica) · {} payload/day · {} on the wire/day",
        count(plan.day_one.events_per_day),
        gib(plan.day_one.stored_gib_per_day),
        gib(plan.day_one.payload_bytes_per_day / crate::units::BYTES_PER_GIB),
        gib(plan.day_one.kafka_gib_per_day)
    )?;
    let total: f64 = plan.events.iter().map(|e| e.stored_bytes_per_day).sum();
    writeln!(
        s,
        "\n  {:<28} {:>12} {:>9} {:>11} {:>7}",
        "event type", "events/day", "B/event", "stored/day", "share"
    )?;
    let mut rest = 0;
    for e in &plan.events {
        let share = if total > 0.0 {
            e.stored_bytes_per_day / total
        } else {
            0.0
        };
        if share < 0.001 {
            rest += 1;
            continue;
        }
        writeln!(
            s,
            "  {:<28} {:>12} {:>9.0} {:>11} {:>6.1}%{}",
            e.event_type,
            count(e.events_per_day),
            e.stored_bytes_per_event(),
            gib(e.stored_bytes_per_day / crate::units::BYTES_PER_GIB),
            share * 100.0,
            if e.size_overridden {
                "  (size override)"
            } else {
                ""
            }
        )?;
    }
    if rest > 0 {
        writeln!(s, "  … {rest} more types under 0.1% each")?;
    }

    writeln!(
        s,
        "\ngrowth (end of year; stored = one replica; cold = past the tiering threshold):"
    )?;
    writeln!(
        s,
        "  {:>4} {:>12} {:>10} {:>10} {:>6} {:>5} {:>12} {:>12} {:>10}",
        "year",
        "events/day",
        "stored",
        "cold",
        "shards",
        "nodes",
        "provisioned",
        "kafka/broker",
        "$/month"
    )?;
    for y in &plan.years {
        writeln!(
            s,
            "  {:>4} {:>12} {:>10} {:>10} {:>6} {:>5} {:>12} {:>12} {:>10.0}",
            y.year,
            count(y.events_per_day),
            gib(y.stored_gib),
            gib(y.cold_gib),
            y.shards,
            y.nodes,
            gib(y.provisioned_gib),
            gib(y.kafka_broker_gib),
            y.monthly_storage_usd
        )?;
    }

    if !plan.scenarios.is_empty() {
        writeln!(s, "\nscenarios (horizon):")?;
        for sc in &plan.scenarios {
            writeln!(
                s,
                "  {:<12} {:>5}×/year  {:>10} stored  {:>3} shards  ${:.0}/month",
                sc.name,
                sc.annual_growth,
                gib(sc.stored_gib_at_horizon),
                sc.shards_at_horizon,
                sc.monthly_usd_at_horizon
            )?;
        }
    }
    if !plan.sensitivity.is_empty() {
        writeln!(
            s,
            "\nsensitivity of horizon storage (measure the top one first):"
        )?;
        for line in &plan.sensitivity {
            writeln!(
                s,
                "  {:<34} {:<18} {:+.1}%",
                line.input,
                line.change,
                line.stored_change * 100.0
            )?;
        }
    }

    writeln!(s, "\nclickhouse tables:")?;
    for t in &plan.tables {
        let window = match t.window {
            Window::Days(d) => format!("{d}d"),
            Window::Unbounded => "no TTL".to_owned(),
        };
        writeln!(
            s,
            "  {:<40} {:<44} {:>7}  {:>7.0} partitions at full window",
            t.id, t.key, window, t.partitions_at_full_window
        )?;
    }
    writeln!(
        s,
        "\ningest: {:.0} events/s at the horizon peak → {:.1} inserts/s (limit {})",
        plan.inserts.peak_events_per_second,
        plan.inserts.inserts_per_second,
        model.ingest.max_inserts_per_second.get()
    )?;
    let k = &plan.kafka;
    let busiest = k
        .topics
        .iter()
        .max_by(|a, b| a.peak_bytes_per_second.total_cmp(&b.peak_bytes_per_second));
    writeln!(
        s,
        "kafka: {} topics × {} partitions × RF {} = {:.0} replicas/broker; chains → {:?}; busiest: {}",
        k.topics.len(),
        model.kafka.deployed_partitions,
        model.kafka.replication,
        k.partition_replicas_per_broker,
        k.chain_partitions,
        busiest.map_or("none".into(), |t| format!(
            "{} at {:.0} B/s peak ({} partition(s) for throughput)",
            t.event_type, t.peak_bytes_per_second, t.partitions_for_throughput
        ))
    )?;
    writeln!(
        s,
        "drift ceiling (EventStoreGrowthAboveCapacityPlan): {} payload bytes/day",
        plan.drift_ceiling_payload_bytes_per_day
    )?;

    let breaches = findings
        .iter()
        .filter(|f| f.severity == Severity::Breach)
        .count();
    writeln!(
        s,
        "\n{}",
        if breaches == 0 {
            "verdict: HELD — no breach at this headroom".to_owned()
        } else {
            format!("verdict: BREACHED — {breaches} breach(es)")
        }
    )?;
    for f in findings {
        let tag = match f.severity {
            Severity::Breach => "BREACH  ",
            Severity::Advisory => "advisory",
        };
        writeln!(s, "  {tag} {}: {}", f.check, f.message)?;
    }
    Ok(())
}

fn count(n: f64) -> String {
    match n {
        n if n >= 1e9 => format!("{:.2}B", n / 1e9),
        n if n >= 1e6 => format!("{:.2}M", n / 1e6),
        n if n >= 1e3 => format!("{:.1}k", n / 1e3),
        n => format!("{n:.1}"),
    }
}

fn gib(g: f64) -> String {
    match g {
        g if g >= 1024.0 => format!("{:.2} TiB", g / 1024.0),
        g if g >= 1.0 => format!("{g:.1} GiB"),
        g => format!("{:.0} MiB", g * 1024.0),
    }
}
