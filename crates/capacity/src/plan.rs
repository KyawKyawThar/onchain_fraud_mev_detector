//! Stage four: every table, the wire, the insert rate, the scenarios — the
//! numbers the checks judge and the report prints. Pure: stages in, plan out.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::corpus::Shapes;
use crate::ddl::TableDef;
use crate::kafka::{self, KafkaPlan};
use crate::key::{KeyContext, PartitionKey};
use crate::model::Model;
use crate::timeline::{Timeline, YearLine};
use crate::units::Positive;
use crate::workload::{EventVolume, Workload};

/// The event store's table, which the workload and the evidence window price.
pub const EVENT_STORE: (&str, &str) = ("event-store", "events");

/// Everything the plan is computed from.
pub struct Inputs<'a> {
    pub model: &'a Model,
    pub shapes: &'a Shapes,
    pub tables: &'a [TableDef],
    pub evidence_days: u32,
    /// Price the event store under this key instead of its migrations' (a what-if).
    pub events_key_override: Option<PartitionKey>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub model: String,
    pub headroom: f64,
    pub evidence_days: u32,
    pub events_key: String,
    pub window_days: u32,
    pub day_one: DayOne,
    pub events: Vec<EventVolume>,
    pub years: Vec<YearLine>,
    pub timeline: Timeline,
    pub tables: Vec<TablePlan>,
    pub kafka: KafkaPlan,
    pub inserts: InsertPlan,
    pub scenarios: Vec<ScenarioLine>,
    pub sensitivity: Vec<SensitivityLine>,
    /// The daily payload bytes above which `EventStoreGrowthAboveCapacityPlan`
    /// fires: 1.25 × the 1× projection at the end of year one.
    pub drift_ceiling_payload_bytes_per_day: u64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DayOne {
    pub events_per_day: f64,
    pub stored_gib_per_day: f64,
    pub payload_bytes_per_day: f64,
    pub kafka_gib_per_day: f64,
}

/// Retention a table's partitions accumulate over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Window {
    Days(u32),
    /// No TTL: the table grows for as long as the platform runs.
    Unbounded,
}

/// One ClickHouse table's partitions.
#[derive(Debug, Clone, Serialize)]
pub struct TablePlan {
    pub id: String,
    pub key: String,
    pub window: Window,
    pub partitions_at_horizon: f64,
    /// Once a whole window is held (the horizon, for an unbounded table).
    pub partitions_at_full_window: f64,
    /// First day the table holds more partitions than `max_parts_in_total`.
    pub parts_limit_day: Option<u32>,
    /// First day one bulk insert block (a restore) can exceed the per-block limit.
    pub insert_block_limit_day: Option<u32>,
    /// Longest window the key keeps under the per-block limit, in days.
    pub max_window_for_insert_limit: Option<u32>,
}

/// Inserts per second into `events` at the horizon's peak.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct InsertPlan {
    pub peak_events_per_second: f64,
    pub inserts_per_second: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioLine {
    pub name: String,
    pub annual_growth: f64,
    pub stored_gib_at_horizon: f64,
    pub shards_at_horizon: u32,
    pub monthly_usd_at_horizon: f64,
}

/// How much year-horizon storage moves when one input moves.
#[derive(Debug, Clone, Serialize)]
pub struct SensitivityLine {
    pub input: &'static str,
    pub change: &'static str,
    pub stored_change: f64,
}

/// Build the plan at `headroom`.
pub fn plan(inputs: &Inputs<'_>, headroom: Positive) -> Result<Plan> {
    let model = inputs.model.clone().with_headroom(headroom);
    let workload = Workload::build(&model, inputs.shapes)?;

    let events_def = inputs
        .tables
        .iter()
        .find(|t| (t.owner.as_str(), t.name.as_str()) == EVENT_STORE)
        .context("no event-store `events` table in the replayed migrations")?;
    let events_key = inputs
        .events_key_override
        .clone()
        .unwrap_or_else(|| events_def.key.clone());
    let window_days = inputs.evidence_days + events_key.expiry_lag_days();
    let timeline = Timeline::walk(&model, &workload, window_days);

    let tables = inputs
        .tables
        .iter()
        .map(|t| {
            let is_events = (t.owner.as_str(), t.name.as_str()) == EVENT_STORE;
            let key = if is_events { &events_key } else { &t.key };
            let window = if is_events {
                Window::Days(window_days)
            } else {
                t.ttl_days.map_or(Window::Unbounded, |d| {
                    Window::Days(d + key.expiry_lag_days())
                })
            };
            table_plan(&model, &workload, t.id(), key, window, is_events)
        })
        .collect();

    let kafka = kafka::plan(
        &model,
        &workload,
        timeline.horizon_growth,
        timeline.years.last().map_or(0.0, |y| y.kafka_broker_gib),
    );
    let inserts = insert_plan(&model, &workload, timeline.horizon_growth);
    let scenarios = scenarios(&model, &workload, window_days);
    let sensitivity = sensitivity(inputs, &model, window_days)?;

    // The drift ceiling is always the 1× projection, whatever headroom this
    // plan was asked for: an alert on production traffic compares against the
    // forecast, not against the margin above it.
    let base = inputs.model.clone();
    let base_workload = Workload::build(&base, inputs.shapes)?;
    let year_one = Timeline::daily_growth(&base).powi(365);
    let drift_ceiling = (base_workload.payload_bytes_per_day() * year_one * 1.25).round() as u64;

    Ok(Plan {
        model: model.name.clone(),
        headroom: headroom.get(),
        evidence_days: inputs.evidence_days,
        events_key: events_key.expression().to_owned(),
        window_days,
        day_one: DayOne {
            events_per_day: workload.events_per_day(),
            stored_gib_per_day: workload.stored_gib_per_day(),
            payload_bytes_per_day: workload.payload_bytes_per_day(),
            kafka_gib_per_day: workload.kafka_gib_per_day(),
        },
        years: timeline.years.clone(),
        events: workload.events.clone(),
        timeline,
        tables,
        kafka,
        inserts,
        scenarios,
        sensitivity,
        drift_ceiling_payload_bytes_per_day: drift_ceiling,
    })
}

fn table_plan(
    model: &Model,
    workload: &Workload,
    id: String,
    key: &PartitionKey,
    window: Window,
    is_events: bool,
) -> TablePlan {
    let ch = &model.clickhouse;
    let horizon = Timeline::horizon_days(model);
    let daily_growth = Timeline::daily_growth(model);
    let (pair_rates, type_rates) = if is_events {
        (workload.pair_rates(), workload.type_rates())
    } else {
        (Vec::new(), Vec::new())
    };
    let event_types = workload.events.len() as f64;
    let ctx_at = |day: usize| KeyContext {
        chains: workload.chains as f64,
        event_types,
        pair_rates: &pair_rates,
        type_rates: &type_rates,
        growth: daily_growth.powi(day as i32),
    };
    let held = |day: usize| match window {
        Window::Days(w) => (day + 1).min(w as usize) as f64,
        Window::Unbounded => (day + 1) as f64,
    };

    let mut parts_limit_day = None;
    let mut insert_block_limit_day = None;
    for day in 0..horizon {
        let partitions = key.count(held(day), &ctx_at(day));
        if parts_limit_day.is_none() && partitions >= ch.max_parts_in_total as f64 {
            parts_limit_day = Some(day as u32 + 1);
        }
        if insert_block_limit_day.is_none()
            && partitions > ch.max_partitions_per_insert_block as f64
        {
            insert_block_limit_day = Some(day as u32 + 1);
        }
        if parts_limit_day.is_some() && insert_block_limit_day.is_some() {
            break;
        }
    }
    let last = horizon.saturating_sub(1);
    // A table with no TTL keeps accumulating partitions after the plan stops
    // looking, so its insert-block cliff is searched past the horizon too — a
    // restore that fails in year nine is still a restore that fails.
    if window == Window::Unbounded && insert_block_limit_day.is_none() {
        let beyond = KeyContext {
            growth: daily_growth.powi(last as i32),
            ..ctx_at(last)
        };
        insert_block_limit_day = (horizon..36_500)
            .find(|&day| {
                key.count((day + 1) as f64, &beyond) > ch.max_partitions_per_insert_block as f64
            })
            .map(|day| day as u32 + 1);
    }
    let partitions_at_horizon = key.count(held(last), &ctx_at(last));
    let full_window_days = match window {
        Window::Days(w) => f64::from(w),
        Window::Unbounded => horizon as f64,
    };
    let partitions_at_full_window = key
        .count(full_window_days, &ctx_at(last))
        .max(partitions_at_horizon);

    // The widest window a restore still fits in one block, found on the same
    // key arithmetic rather than a per-key formula.
    let limit = ch.max_partitions_per_insert_block as f64;
    let mut max_window = None;
    let mut days = 1u32;
    while days <= 36_500 && key.count(f64::from(days), &ctx_at(last)) <= limit {
        max_window = Some(days);
        days += 1;
    }
    let max_window_for_insert_limit = max_window.map(|d| d.saturating_sub(key.expiry_lag_days()));

    TablePlan {
        id,
        key: key.expression().to_owned(),
        window,
        partitions_at_horizon,
        partitions_at_full_window,
        parts_limit_day,
        insert_block_limit_day,
        max_window_for_insert_limit,
    }
}

/// A batch loop flushes when its batch fills or its wait expires, whichever is
/// first. Under load that is `rate / max_rows` per consumer; on a quiet stream
/// at most one flush per wait. So the insert rate is the larger of the two,
/// never more than one insert per event.
fn insert_plan(model: &Model, workload: &Workload, horizon_growth: f64) -> InsertPlan {
    let ingest = &model.ingest;
    let consumers = f64::from(ingest.consumers);
    let peak =
        workload.events_per_day() * horizon_growth / 86_400.0 * model.kafka.peak_to_mean.get();
    let per_consumer = peak / consumers;
    let when_full = per_consumer / ingest.batch_max_rows as f64;
    let when_waiting = (1_000.0 / ingest.batch_max_wait_ms as f64).min(per_consumer);
    InsertPlan {
        peak_events_per_second: peak,
        inserts_per_second: consumers * when_full.max(when_waiting),
    }
}

fn scenarios(model: &Model, workload: &Workload, window_days: u32) -> Vec<ScenarioLine> {
    model
        .scenarios
        .iter()
        .map(|scenario| {
            let grown = model.clone().with_growth(scenario.annual_growth);
            let timeline = Timeline::walk(&grown, workload, window_days);
            let last = timeline.years.last().copied();
            ScenarioLine {
                name: scenario.name.clone(),
                annual_growth: scenario.annual_growth.get(),
                stored_gib_at_horizon: last.map_or(0.0, |y| y.stored_gib),
                shards_at_horizon: last.map_or(0, |y| y.shards),
                monthly_usd_at_horizon: last.map_or(0.0, |y| y.monthly_storage_usd),
            }
        })
        .collect()
}

type Perturbation = (&'static str, &'static str, fn(&mut Model));

/// Each input moved by a plausible error, one at a time, ranked by effect on
/// horizon storage — which of the assumptions to measure first.
fn sensitivity(
    inputs: &Inputs<'_>,
    scaled: &Model,
    window_days: u32,
) -> Result<Vec<SensitivityLine>> {
    let perturbations: [Perturbation; 5] = [
        ("annual_growth", "+10%", |m| {
            m.annual_growth = Positive::new(m.annual_growth.get() * 1.1).expect("positive");
        }),
        ("clickhouse.compression_ratio", "-25%", |m| {
            m.clickhouse.compression_ratio.value =
                (m.clickhouse.compression_ratio.value * 0.75).max(1.0);
        }),
        ("active_addresses_per_day", "+25%", |m| {
            m.active_addresses_per_day =
                crate::units::NonNegative::new(m.active_addresses_per_day.get() * 1.25)
                    .expect("non-negative");
        }),
        ("api.mean_requests_per_second", "+25%", |m| {
            m.api.mean_requests_per_second =
                crate::units::NonNegative::new(m.api.mean_requests_per_second.get() * 1.25)
                    .expect("non-negative");
        }),
        (
            "chains[].alerting_block_fraction",
            "x2 (capped at 1)",
            |m| {
                for chain in &mut m.chains {
                    chain.alerting_block_fraction = crate::units::Fraction::new(
                        (chain.alerting_block_fraction.get() * 2.0).min(1.0),
                    )
                    .expect("fraction");
                }
            },
        ),
    ];
    let base_workload = Workload::build(scaled, inputs.shapes)?;
    let base = Timeline::walk(scaled, &base_workload, window_days).stored_gib_at_horizon();
    let mut lines = Vec::with_capacity(perturbations.len());
    for (input, change, apply) in perturbations {
        let mut moved = scaled.clone();
        apply(&mut moved);
        let workload = Workload::build(&moved, inputs.shapes)?;
        let stored = Timeline::walk(&moved, &workload, window_days).stored_gib_at_horizon();
        lines.push(SensitivityLine {
            input,
            change,
            stored_change: if base > 0.0 { stored / base - 1.0 } else { 0.0 },
        });
    }
    lines.sort_by(|a, b| b.stored_change.abs().total_cmp(&a.stored_change.abs()));
    Ok(lines)
}
