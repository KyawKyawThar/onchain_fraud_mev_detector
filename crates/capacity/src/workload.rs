//! Stage one: the day-one workload, per event type.
//!
//! Rates × sizes, before growth or time. Everything downstream — storage over
//! the horizon, partition occupancy, Kafka throughput, insert rate — reads this
//! stage's output and never the raw model, so a rate is interpreted once.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::corpus::{KeyKind, Shapes};
use crate::model::Model;
use crate::units::BYTES_PER_GIB;

/// One event type on day one.
#[derive(Debug, Clone, Serialize)]
pub struct EventVolume {
    pub event_type: String,
    pub events_per_day: f64,
    /// Daily events per chain, a global driver spread evenly across chains.
    pub per_chain: Vec<f64>,
    /// Uncompressed `payload` column bytes per day.
    pub payload_bytes_per_day: f64,
    /// Bytes on disk per day, one replica.
    pub stored_bytes_per_day: f64,
    /// Kafka record bytes per day.
    pub envelope_bytes_per_day: f64,
    pub key: KeyKind,
    /// Whether any term overrides the corpus-measured payload size.
    pub size_overridden: bool,
}

impl EventVolume {
    pub fn stored_bytes_per_event(&self) -> f64 {
        if self.events_per_day > 0.0 {
            self.stored_bytes_per_day / self.events_per_day
        } else {
            0.0
        }
    }
}

/// Every event type on day one, largest storage first.
#[derive(Debug, Clone, Serialize)]
pub struct Workload {
    pub events: Vec<EventVolume>,
    pub chains: usize,
}

impl Workload {
    /// Build from a model that is already scaled (headroom, scenario).
    pub fn build(model: &Model, shapes: &Shapes) -> Result<Self> {
        let compression = model.clickhouse.compression_ratio.value;
        let index = 1.0 + model.clickhouse.index_overhead_fraction.get();
        let chains = model.chains.len();
        let mut events = Vec::with_capacity(model.events.len());
        for (event_type, rate) in &model.events {
            let shape = shapes.get(event_type).with_context(|| {
                format!("{event_type} has no schema corpus fixture, so its row size is unknown")
            })?;
            let mut per_chain = vec![0.0; chains];
            let (mut payload, mut stored, mut envelope) = (0.0, 0.0, 0.0);
            for term in &rate.terms {
                let payload_size =
                    term.payload_bytes.map_or(shape.payload_bytes, |b| b.get()) as f64;
                let row = payload_size + shape.column_bytes as f64;
                let record =
                    shape.envelope_bytes as f64 - shape.payload_bytes as f64 + payload_size;
                let term_rates: Vec<f64> = model
                    .chains
                    .iter()
                    .map(|chain| model.driver_per_day(term.driver, chain) * term.per.get())
                    .collect();
                let daily = if term.driver.is_chain_scoped() {
                    for (slot, r) in per_chain.iter_mut().zip(&term_rates) {
                        *slot += r;
                    }
                    term_rates.iter().sum::<f64>()
                } else {
                    let global = term_rates[0];
                    for slot in &mut per_chain {
                        *slot += global / chains as f64;
                    }
                    global
                };
                payload += daily * payload_size;
                stored += daily * row / compression * index;
                envelope += daily * record;
            }
            events.push(EventVolume {
                event_type: event_type.clone(),
                events_per_day: per_chain.iter().sum(),
                per_chain,
                payload_bytes_per_day: payload,
                stored_bytes_per_day: stored,
                envelope_bytes_per_day: envelope,
                key: shape.key,
                size_overridden: rate.terms.iter().any(|t| t.payload_bytes.is_some()),
            });
        }
        events.sort_by(|a, b| b.stored_bytes_per_day.total_cmp(&a.stored_bytes_per_day));
        Ok(Self { events, chains })
    }

    pub fn events_per_day(&self) -> f64 {
        self.events.iter().map(|e| e.events_per_day).sum()
    }

    pub fn stored_gib_per_day(&self) -> f64 {
        self.events
            .iter()
            .map(|e| e.stored_bytes_per_day)
            .sum::<f64>()
            / BYTES_PER_GIB
    }

    pub fn payload_bytes_per_day(&self) -> f64 {
        self.events.iter().map(|e| e.payload_bytes_per_day).sum()
    }

    pub fn kafka_gib_per_day(&self) -> f64 {
        self.events
            .iter()
            .map(|e| e.envelope_bytes_per_day)
            .sum::<f64>()
            / BYTES_PER_GIB
    }

    /// Daily rate of every (chain, event type) pair that occurs.
    pub fn pair_rates(&self) -> Vec<f64> {
        self.events
            .iter()
            .flat_map(|e| e.per_chain.iter().copied())
            .filter(|r| *r > 0.0)
            .collect()
    }

    /// Daily rate of every event type that occurs.
    pub fn type_rates(&self) -> Vec<f64> {
        self.events
            .iter()
            .map(|e| e.events_per_day)
            .filter(|r| *r > 0.0)
            .collect()
    }
}
