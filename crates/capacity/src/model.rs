//! The capacity profile: what load the platform must hold, as a committed value.
//!
//! Like the load test's profiles, nothing in the source documents states these
//! numbers, so they live here with their derivation written down. The shape is
//! **driver × multiplier**: an event type's daily volume is a sum of terms such
//! as "1.5 per alerting block" or "1 per API request", so a projection moves by
//! changing a driver once, and every event type that depends on it follows.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::units::{AtLeastOne, Bytes, FillCeiling, Fraction, Gib, NonNegative, Positive};

/// A committed capacity profile. See `crates/capacity/model.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub name: String,
    /// Where the projection came from — printed with the plan.
    pub rationale: String,
    /// Years of growth to plan across. Longer than the evidence window, so the
    /// plan shows the store at steady state rather than still filling.
    pub horizon_years: u32,
    /// Volume multiplier per year, applied to every driver.
    pub annual_growth: Positive,
    /// Alternative growth paths, reported beside the base plan so a reader sees
    /// how far the conclusions move if the forecast is wrong.
    pub scenarios: Vec<Scenario>,
    pub chains: Vec<ChainLoad>,
    pub api: ApiLoad,
    /// Addresses the embedding sweep refreshes per day, across all chains.
    pub active_addresses_per_day: NonNegative,
    pub customers: NonNegative,
    /// Keyed by `DomainEvent` variant name. Exhaustive in both directions:
    /// `tests/committed.rs` fails on a variant with no rate or a rate with no
    /// variant, so a new event type cannot ship unpriced.
    pub events: BTreeMap<String, EventRate>,
    pub ingest: IngestParams,
    pub clickhouse: ClickhouseParams,
    pub kafka: KafkaParams,
    pub cost: CostParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    pub annual_growth: Positive,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainLoad {
    pub chain: u64,
    /// The chain's own cadence — a mean, not the load test's burst rate.
    pub blocks_per_second: Positive,
    pub txs_per_block: NonNegative,
    /// Share of blocks that produce at least one alert.
    pub alerting_block_fraction: Fraction,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiLoad {
    /// Daily mean, not peak: storage integrates the mean.
    pub mean_requests_per_second: NonNegative,
    /// Share of requests that are `/screen` decisions.
    pub screen_share: Fraction,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRate {
    pub terms: Vec<Term>,
    pub rationale: String,
}

/// One contribution to an event type's volume.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Term {
    pub driver: Driver,
    pub per: NonNegative,
    /// The payload size of *this term's* events, when it differs from the
    /// corpus fixture — a production-sized list the fixture abbreviates, or the
    /// two shapes one type is published in (a full embedding and a refresh).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_bytes: Option<Bytes>,
}

/// What an event's volume is proportional to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Driver {
    /// Per block, on each chain.
    Block,
    /// Per transaction, on each chain.
    Transaction,
    /// Per block that alerts, on each chain.
    AlertingBlock,
    /// Per public API request.
    ApiRequest,
    /// Per `/screen` decision.
    Screen,
    /// Per active address per day.
    ActiveAddress,
    /// Per customer per day.
    Customer,
    /// A fixed count per day (operational cadence). Not scaled by headroom — a
    /// nightly job does not run 1.5 times a night under load.
    Day,
}

impl Driver {
    /// Whether the driver is counted separately on every chain.
    pub fn is_chain_scoped(self) -> bool {
        matches!(
            self,
            Driver::Block | Driver::Transaction | Driver::AlertingBlock
        )
    }
}

/// A parameter that is neither a projection nor measured from the repo, with
/// its provenance attached so the report can say which numbers are guesses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Estimate {
    pub value: f64,
    pub basis: Basis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Basis {
    /// Not yet measured. `why` says what the number rests on.
    Assumed { why: String },
    /// Measured: when, and by what procedure.
    Measured { on: String, how: String },
}

impl Estimate {
    pub fn is_assumed(&self) -> bool {
        matches!(self.basis, Basis::Assumed { .. })
    }
}

/// How the event store's Kafka ingest writes, as deployed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestParams {
    /// `EVENT_STORE_BATCH_MAX_ROWS` in the deployed config map, pinned by test.
    pub batch_max_rows: u64,
    /// `EVENT_STORE_BATCH_MAX_WAIT_MS` in the deployed config map, pinned by test.
    pub batch_max_wait_ms: u64,
    /// Ingest consumers at the horizon (each one flushes independently).
    pub consumers: u32,
    /// Inserts per second into `events` the plan will tolerate.
    pub max_inserts_per_second: Positive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClickhouseParams {
    /// Uncompressed row bytes ÷ bytes on disk for the `events` table.
    pub compression_ratio: Estimate,
    /// Skip indexes, marks and primary index, as a fraction of column data.
    pub index_overhead_fraction: NonNegative,
    /// Copies of every shard (§20: replicated).
    pub replicas: u32,
    pub node_disk_gib: Gib,
    /// Merges need free space to rewrite parts into.
    pub max_disk_fill: FillCeiling,
    /// Our ceiling on partitions per table.
    pub partition_budget: u64,
    /// Server `max_parts_in_total`: past this every insert is refused.
    pub max_parts_in_total: u64,
    /// Server `max_partitions_per_insert_block`.
    pub max_partitions_per_insert_block: u64,
    /// `deploy/k8s/base/infra/clickhouse.yaml`'s PVC request, pinned by test.
    pub deployed_pvc_gib: Gib,
    /// The sharding expression the event store will be distributed by. A
    /// decision before it is a deployment: `ReplacingMergeTree` only collapses
    /// duplicates within one shard, so the key must send every copy of an
    /// event to the same shard — a function of `event_id` alone.
    pub shard_key: String,
    /// Storage price for the cold volume, when tiering is planned.
    pub cold_after_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KafkaParams {
    /// `KAFKA_TOPIC_PARTITIONS` in the deployed config map, pinned by test.
    pub deployed_partitions: u32,
    /// Production replication factor (Epic A: ≥ 3).
    pub replication: u32,
    pub brokers: u32,
    pub broker_disk_gib: Gib,
    pub max_disk_fill: FillCeiling,
    /// Topic retention — the wire, not the record.
    pub retention_days: Positive,
    pub partition_throughput_bytes_per_second: Estimate,
    pub max_partition_replicas_per_broker: u64,
    /// Peak ÷ daily mean byte rate a partition must absorb.
    pub peak_to_mean: AtLeastOne,
    /// `deploy/k8s/base/infra/kafka.yaml`'s PVC request, pinned by test.
    pub deployed_pvc_gib: Gib,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostParams {
    pub block_storage_usd_per_gib_month: Estimate,
    /// Object storage behind a cold volume, when `clickhouse.cold_after_days`
    /// is set.
    pub cold_storage_usd_per_gib_month: Estimate,
}

impl Model {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading the capacity model at {}", path.display()))?;
        let model: Self = serde_json::from_str(&raw)
            .with_context(|| format!("parsing the capacity model at {}", path.display()))?;
        model.validate()?;
        Ok(model)
    }

    /// Scale the load by `headroom`. Rates scale; the shape — txs per block,
    /// alerting fraction, screen share, fixed daily cadences — does not.
    #[must_use]
    pub fn with_headroom(mut self, headroom: Positive) -> Self {
        let h = headroom.get();
        let scale = |v: f64| v * h;
        for chain in &mut self.chains {
            chain.blocks_per_second = Positive::new(scale(chain.blocks_per_second.get()))
                .expect("a positive rate times a positive headroom is positive");
        }
        self.api.mean_requests_per_second =
            NonNegative::new(scale(self.api.mean_requests_per_second.get())).expect("non-negative");
        self.active_addresses_per_day =
            NonNegative::new(scale(self.active_addresses_per_day.get())).expect("non-negative");
        self.customers = NonNegative::new(scale(self.customers.get())).expect("non-negative");
        self
    }

    /// The same model on another growth path.
    #[must_use]
    pub fn with_growth(mut self, annual_growth: Positive) -> Self {
        self.annual_growth = annual_growth;
        self
    }

    /// Units of `driver` per day — on `chain` for a chain-scoped driver, and
    /// globally (the `chain` argument ignored) otherwise.
    pub fn driver_per_day(&self, driver: Driver, chain: &ChainLoad) -> f64 {
        const SECONDS_PER_DAY: f64 = 86_400.0;
        let blocks = chain.blocks_per_second.get() * SECONDS_PER_DAY;
        let requests = self.api.mean_requests_per_second.get() * SECONDS_PER_DAY;
        match driver {
            Driver::Block => blocks,
            Driver::Transaction => blocks * chain.txs_per_block.get(),
            Driver::AlertingBlock => blocks * chain.alerting_block_fraction.get(),
            Driver::ApiRequest => requests,
            Driver::Screen => requests * self.api.screen_share.get(),
            Driver::ActiveAddress => self.active_addresses_per_day.get(),
            Driver::Customer => self.customers.get(),
            Driver::Day => 1.0,
        }
    }

    /// Every [`Estimate`] in the model, by name.
    pub fn estimates(&self) -> Vec<(&'static str, &Estimate)> {
        vec![
            (
                "clickhouse.compression_ratio",
                &self.clickhouse.compression_ratio,
            ),
            (
                "kafka.partition_throughput_bytes_per_second",
                &self.kafka.partition_throughput_bytes_per_second,
            ),
            (
                "cost.block_storage_usd_per_gib_month",
                &self.cost.block_storage_usd_per_gib_month,
            ),
            (
                "cost.cold_storage_usd_per_gib_month",
                &self.cost.cold_storage_usd_per_gib_month,
            ),
        ]
    }

    /// Cross-field rules. Single-field domains are already types.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=30).contains(&self.horizon_years),
            "horizon_years must be 1..=30, got {}",
            self.horizon_years
        );
        ensure!(!self.chains.is_empty(), "the model names no chains");
        let mut seen = BTreeSet::new();
        for chain in &self.chains {
            ensure!(
                seen.insert(chain.chain),
                "chain {} is listed twice",
                chain.chain
            );
        }
        ensure!(!self.events.is_empty(), "the model prices no event types");
        for (event_type, rate) in &self.events {
            ensure!(
                !rate.terms.is_empty(),
                "{event_type}: no terms — an event that never occurs still needs `per: 0` \
                 and a rationale saying why"
            );
        }
        let mut names = BTreeSet::new();
        for scenario in &self.scenarios {
            ensure!(
                names.insert(&scenario.name),
                "scenario {} is listed twice",
                scenario.name
            );
        }
        ensure!(
            self.ingest.batch_max_rows >= 1,
            "ingest.batch_max_rows must be >= 1"
        );
        ensure!(
            self.ingest.batch_max_wait_ms >= 1,
            "ingest.batch_max_wait_ms must be >= 1"
        );
        ensure!(self.ingest.consumers >= 1, "ingest.consumers must be >= 1");
        let ch = &self.clickhouse;
        ensure!(
            ch.compression_ratio.value.is_finite() && ch.compression_ratio.value >= 1.0,
            "clickhouse.compression_ratio must be >= 1"
        );
        ensure!(ch.replicas >= 1, "clickhouse.replicas must be >= 1");
        ensure!(
            ch.partition_budget > 0
                && ch.max_parts_in_total > 0
                && ch.max_partitions_per_insert_block > 0,
            "clickhouse limits must be positive"
        );
        if let Some(days) = ch.cold_after_days {
            ensure!(days >= 1, "clickhouse.cold_after_days must be >= 1");
        }
        let k = &self.kafka;
        ensure!(
            k.deployed_partitions >= 1,
            "kafka.deployed_partitions must be >= 1"
        );
        ensure!(
            k.replication >= 1 && k.replication <= k.brokers,
            "kafka.replication must be 1..=brokers ({}), got {}",
            k.brokers,
            k.replication
        );
        ensure!(
            k.partition_throughput_bytes_per_second.value > 0.0,
            "kafka.partition_throughput_bytes_per_second must be positive"
        );
        ensure!(
            k.max_partition_replicas_per_broker > 0,
            "kafka.max_partition_replicas_per_broker must be positive"
        );
        for (name, estimate) in [
            (
                "cost.block_storage_usd_per_gib_month",
                &self.cost.block_storage_usd_per_gib_month,
            ),
            (
                "cost.cold_storage_usd_per_gib_month",
                &self.cost.cold_storage_usd_per_gib_month,
            ),
        ] {
            ensure!(estimate.value >= 0.0, "{name} must be >= 0");
        }
        Ok(())
    }
}
