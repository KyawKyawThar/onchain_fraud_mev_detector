//! Stage two: the event store over the growth horizon.
//!
//! Daily volume grows continuously at the model's annual rate. The store holds
//! a sliding window of evidence days plus the key's expiry lag, so its size on
//! day `d` is the sum of the last `window` days of volume — which under growth
//! never plateaus but tracks the growth rate once the window is full. Walked a
//! day at a time rather than in closed form, so one loop answers every "on
//! which day does X first happen".

use serde::Serialize;

use crate::model::Model;
use crate::units::BYTES_PER_GIB;
use crate::workload::Workload;

pub const DAYS_PER_YEAR: usize = 365;

/// The store at the end of a year.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct YearLine {
    pub year: u32,
    pub events_per_day: f64,
    /// One replica, on disk.
    pub stored_gib: f64,
    /// Of `stored_gib`, the part older than the tiering threshold.
    pub cold_gib: f64,
    pub shards: u32,
    pub nodes: u32,
    pub provisioned_gib: f64,
    /// Used, per broker.
    pub kafka_broker_gib: f64,
    pub monthly_storage_usd: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Timeline {
    pub window_days: u32,
    pub years: Vec<YearLine>,
    /// Growth multiplier on the horizon's last day.
    pub horizon_growth: f64,
    /// First day the deployed single-node ClickHouse volume passes its ceiling.
    pub deployed_clickhouse_full_day: Option<u32>,
    /// First day the deployed single-broker Kafka volume passes its ceiling.
    pub deployed_kafka_full_day: Option<u32>,
}

impl Timeline {
    pub fn horizon_days(model: &Model) -> usize {
        model.horizon_years as usize * DAYS_PER_YEAR
    }

    pub fn daily_growth(model: &Model) -> f64 {
        model.annual_growth.get().powf(1.0 / DAYS_PER_YEAR as f64)
    }

    /// Walk `model` (scaled) with `workload` and a retention `window_days`.
    pub fn walk(model: &Model, workload: &Workload, window_days: u32) -> Self {
        let ch = &model.clickhouse;
        let k = &model.kafka;
        let window = window_days as usize;
        let cold_after = ch.cold_after_days.map(|d| d as usize);
        let horizon = Self::horizon_days(model);
        let daily_growth = Self::daily_growth(model);
        let block_price = model.cost.block_storage_usd_per_gib_month.value;
        let cold_price = model.cost.cold_storage_usd_per_gib_month.value;
        let day_one = workload.stored_gib_per_day();
        let kafka_day_one = workload.kafka_gib_per_day();

        let mut history: Vec<f64> = Vec::with_capacity(horizon);
        let mut stored = 0.0;
        let mut years = Vec::with_capacity(model.horizon_years as usize);
        let mut ch_full = None;
        let mut kafka_full = None;
        for day in 0..horizon {
            let growth = daily_growth.powi(day as i32);
            let today = day_one * growth;
            history.push(today);
            stored += today;
            if history.len() > window {
                stored -= history[history.len() - 1 - window];
            }
            let label = day as u32 + 1;
            if ch_full.is_none() && stored > ch.deployed_pvc_gib.get() * ch.max_disk_fill.get() {
                ch_full = Some(label);
            }
            let kafka_held = kafka_day_one * growth * k.retention_days.get();
            if kafka_full.is_none() && kafka_held > k.deployed_pvc_gib.get() * k.max_disk_fill.get()
            {
                kafka_full = Some(label);
            }
            if (day + 1) % DAYS_PER_YEAR == 0 {
                let held = history.len().min(window);
                let hot_days = cold_after.map_or(held, |after| after.min(held));
                let hot: f64 = history[history.len() - hot_days..].iter().sum();
                let cold_gib = (stored - hot).max(0.0);
                // Shards are sized by what sits on local disk; a cold volume
                // lives in object storage and is priced separately.
                let local = if cold_after.is_some() { hot } else { stored };
                let shards = ((local / (ch.node_disk_gib.get() * ch.max_disk_fill.get())).ceil()
                    as u32)
                    .max(1);
                let nodes = shards * ch.replicas;
                let provisioned_gib = f64::from(nodes) * ch.node_disk_gib.get();
                let kafka_broker_gib = kafka_held * f64::from(k.replication) / f64::from(k.brokers);
                years.push(YearLine {
                    year: ((day + 1) / DAYS_PER_YEAR) as u32,
                    events_per_day: workload.events_per_day() * growth,
                    stored_gib: stored,
                    cold_gib,
                    shards,
                    nodes,
                    provisioned_gib,
                    kafka_broker_gib,
                    monthly_storage_usd: (provisioned_gib
                        + f64::from(k.brokers) * k.broker_disk_gib.get())
                        * block_price
                        + cold_gib * f64::from(ch.replicas) * cold_price,
                });
            }
        }
        Self {
            window_days,
            years,
            horizon_growth: daily_growth.powi(horizon as i32 - 1),
            deployed_clickhouse_full_day: ch_full,
            deployed_kafka_full_day: kafka_full,
        }
    }

    pub fn stored_gib_at_horizon(&self) -> f64 {
        self.years.last().map_or(0.0, |y| y.stored_gib)
    }
}

/// Unused-bytes guard: a GiB count back to bytes, for the report's MiB rendering.
pub fn gib_to_bytes(gib: f64) -> f64 {
    gib * BYTES_PER_GIB
}
