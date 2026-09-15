//! Stage three (wire): topics at the horizon, placed the way the producer
//! places them.
//!
//! The partition a record lands on is `events::partitioning::partition_for_key`
//! — the same function `event_bus::KafkaEventSink` calls — so the plan's
//! answer to "how many partitions does a chain-keyed topic really use" is the
//! producer's answer, not an approximation of librdkafka's hash.

use events::partitioning::partition_for_key;
use events::primitives::Chain;
use events::PartitionKey as WireKey;
use serde::Serialize;

use crate::corpus::KeyKind;
use crate::model::Model;
use crate::workload::Workload;

const SECONDS_PER_DAY: f64 = 86_400.0;

/// One topic at the horizon.
#[derive(Debug, Clone, Serialize)]
pub struct TopicLine {
    pub event_type: String,
    pub key: KeyKind,
    pub peak_bytes_per_second: f64,
    pub partitions_for_throughput: u32,
    /// Partitions a consumer group can actually spread across.
    pub consumer_parallelism: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct KafkaPlan {
    pub topics: Vec<TopicLine>,
    pub partition_replicas_per_broker: f64,
    pub broker_disk_gib_at_horizon: f64,
    /// Each chain's partition at the deployed count.
    pub chain_partitions: Vec<(u64, u32)>,
    /// Distinct partitions the chain keys occupy.
    pub chain_parallelism: u32,
}

/// The partition `chain`'s records land on at `partitions`.
pub fn chain_partition(chain: u64, partitions: u32) -> u32 {
    partition_for_key(
        WireKey::Chain(Chain(chain)).to_string().as_bytes(),
        partitions,
    )
}

pub fn plan(
    model: &Model,
    workload: &Workload,
    horizon_growth: f64,
    broker_disk_gib: f64,
) -> KafkaPlan {
    let k = &model.kafka;
    let chain_partitions: Vec<(u64, u32)> = model
        .chains
        .iter()
        .map(|c| (c.chain, chain_partition(c.chain, k.deployed_partitions)))
        .collect();
    let chain_parallelism = {
        let mut used: Vec<u32> = chain_partitions.iter().map(|(_, p)| *p).collect();
        used.sort_unstable();
        used.dedup();
        used.len() as u32
    };
    let topics = workload
        .events
        .iter()
        .map(|e| {
            let peak =
                e.envelope_bytes_per_day * horizon_growth / SECONDS_PER_DAY * k.peak_to_mean.get();
            TopicLine {
                event_type: e.event_type.clone(),
                key: e.key,
                peak_bytes_per_second: peak,
                partitions_for_throughput: ((peak / k.partition_throughput_bytes_per_second.value)
                    .ceil() as u32)
                    .max(1),
                consumer_parallelism: match e.key {
                    KeyKind::Chain => chain_parallelism,
                    KeyKind::Business => k.deployed_partitions,
                },
            }
        })
        .collect();
    KafkaPlan {
        topics,
        partition_replicas_per_broker: workload.events.len() as f64
            * f64::from(k.deployed_partitions)
            * f64::from(k.replication)
            / f64::from(k.brokers),
        broker_disk_gib_at_horizon: broker_disk_gib,
        chain_partitions,
        chain_parallelism,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_chains_get_their_slots_at_every_count() {
        for count in [3, 12] {
            assert_eq!(chain_partition(1, count), 0);
            assert_eq!(chain_partition(8453, count), 1);
        }
    }
}
