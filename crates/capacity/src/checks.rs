//! Which of the plan's numbers are a build failure — as a registry of
//! independent checks, each with a stable id.
//!
//! **A breach is a decision that is expensive to change later**: a partition
//! key or engine (a table rewrite), a shard key (a cluster rebuild), a Kafka
//! partition count (growing it re-maps every business key), an ingest shape
//! that trips a server limit. Those fail the gate at 1.5× headroom, because the
//! cheapest moment to change them is before there is data.
//!
//! **An advisory is a purchase**: shards, disks, brokers, a bill. Those scale
//! with money on the day they are needed, and failing a build on "a second
//! shard in 2028" is a gate people learn to disable. They are reported with the
//! day they arrive.
//!
//! One check per concern, so a new table or a new limit is a new entry rather
//! than another branch in a function everyone edits — the shape of copilot's
//! `CheckRegistry`.

use serde::Serialize;

use crate::corpus::KeyKind;
use crate::model::Model;
use crate::plan::{Plan, Window};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Breach,
    Advisory,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// The check's stable id.
    pub check: &'static str,
    pub message: String,
}

/// What every check reads.
pub struct Context<'a> {
    pub model: &'a Model,
    pub plan: &'a Plan,
}

pub trait Check: Send + Sync {
    fn id(&self) -> &'static str;
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding>;
}

/// Every check, breaches first.
pub fn registry() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(PartsLimit),
        Box::new(PartitionBudget),
        Box::new(InsertBlock),
        Box::new(InsertRate),
        Box::new(ShardKey),
        Box::new(KafkaThroughput),
        Box::new(KafkaReplicas),
        Box::new(ChainPlacement),
        Box::new(Shards),
        Box::new(DeployedVolumes),
        Box::new(BrokerDisk),
        Box::new(RetentionHeadroom),
        Box::new(UnboundedTables),
        Box::new(Assumptions),
    ]
}

/// A table without a TTL has no retention decision at all (conventions §18),
/// and grows for as long as the platform runs.
struct UnboundedTables;
impl Check for UnboundedTables {
    fn id(&self) -> &'static str {
        "clickhouse.unbounded_tables"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let ids: Vec<&str> = ctx
            .plan
            .tables
            .iter()
            .filter(|t| t.window == Window::Unbounded && t.id != "event-store/events")
            .map(|t| t.id.as_str())
            .collect();
        if ids.is_empty() {
            return Vec::new();
        }
        vec![advisory(
            self.id(),
            format!(
                "no TTL — these tables have no retention decision and grow without bound: {}. \
                 Each is a derived projection or a metering record whose lifetime is a product \
                 or billing decision, not a storage one; decide it before the partition count \
                 does",
                ids.join(", ")
            ),
        )]
    }
}

pub fn judge(model: &Model, plan: &Plan) -> Vec<Finding> {
    let ctx = Context { model, plan };
    let mut findings: Vec<Finding> = registry().iter().flat_map(|c| c.judge(&ctx)).collect();
    findings.sort_by_key(|f| f.severity != Severity::Breach);
    findings
}

pub fn has_breach(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Breach)
}

fn breach(check: &'static str, message: String) -> Finding {
    Finding {
        severity: Severity::Breach,
        check,
        message,
    }
}

fn advisory(check: &'static str, message: String) -> Finding {
    Finding {
        severity: Severity::Advisory,
        check,
        message,
    }
}

fn horizon_days(model: &Model) -> u32 {
    model.horizon_years * 365
}

/// A table that passes `max_parts_in_total` refuses every insert. Inside the
/// window (or the horizon, for a table that never expires) it is a breach.
struct PartsLimit;
impl Check for PartsLimit {
    fn id(&self) -> &'static str {
        "clickhouse.max_parts_in_total"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let limit = ctx.model.clickhouse.max_parts_in_total;
        ctx.plan
            .tables
            .iter()
            .filter_map(|t| {
                let at_window = t.partitions_at_full_window >= limit as f64;
                match (t.parts_limit_day, at_window) {
                    (Some(day), _) => Some(breach(
                        self.id(),
                        format!(
                            "{} (PARTITION BY {}) passes max_parts_in_total ({limit}) on day {day} \
                             (year {:.1}): every insert is refused from then on",
                            t.id,
                            t.key,
                            f64::from(day) / 365.0
                        ),
                    )),
                    (None, true) => Some(breach(
                        self.id(),
                        format!(
                            "{} (PARTITION BY {}) reaches {:.0} partitions once its window is full, \
                             past max_parts_in_total ({limit})",
                            t.id, t.key, t.partitions_at_full_window
                        ),
                    )),
                    _ => None,
                }
            })
            .collect()
    }
}

struct PartitionBudget;
impl Check for PartitionBudget {
    fn id(&self) -> &'static str {
        "clickhouse.partition_budget"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let budget = ctx.model.clickhouse.partition_budget as f64;
        ctx.plan
            .tables
            .iter()
            .filter(|t| t.partitions_at_full_window > budget)
            .map(|t| {
                breach(
                    self.id(),
                    format!(
                        "{} holds {:.0} partitions at a full window, over the budget of {budget} — \
                         merges, startup and metadata all scale with partition count",
                        t.id, t.partitions_at_full_window
                    ),
                )
            })
            .collect()
    }
}

/// A restore replays rows in the dump's order, so one insert block may touch
/// every partition the table holds.
struct InsertBlock;
impl Check for InsertBlock {
    fn id(&self) -> &'static str {
        "clickhouse.max_partitions_per_insert_block"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let limit = ctx.model.clickhouse.max_partitions_per_insert_block;
        let horizon = horizon_days(ctx.model);
        ctx.plan
            .tables
            .iter()
            .filter_map(|t| match t.window {
                Window::Days(_) if t.partitions_at_full_window > limit as f64 => Some(breach(
                    self.id(),
                    format!(
                        "a bulk insert into {} (a restore) can touch {:.0} partitions, over the \
                         server limit of {limit}: the restore throws",
                        t.id, t.partitions_at_full_window
                    ),
                )),
                Window::Unbounded => t.insert_block_limit_day.map(|day| {
                    let message = format!(
                        "{} has no TTL, so its partitions grow without bound; a restore of it \
                         exceeds the insert-block limit ({limit}) from day {day} (year {:.1})",
                        t.id,
                        f64::from(day) / 365.0
                    );
                    if day <= horizon {
                        breach(self.id(), message)
                    } else {
                        advisory(self.id(), message)
                    }
                }),
                Window::Days(_) => None,
            })
            .collect()
    }
}

/// Every insert is an on-disk part. The ingest shape decides the rate, and the
/// shape is a deploy-time decision, so an ingest that would out-insert the
/// merges is a breach.
struct InsertRate;
impl Check for InsertRate {
    fn id(&self) -> &'static str {
        "event-store.inserts_per_second"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let limit = ctx.model.ingest.max_inserts_per_second.get();
        let inserts = ctx.plan.inserts;
        if inserts.inserts_per_second <= limit {
            return Vec::new();
        }
        vec![breach(
            self.id(),
            format!(
                "at the horizon's peak ({:.0} events/s) the ingest inserts {:.0} times a second into \
                 events, over {limit:.0}: each insert is a part, and ClickHouse throttles then \
                 refuses inserts that outrun its merges. Raise EVENT_STORE_BATCH_MAX_ROWS or \
                 EVENT_STORE_BATCH_MAX_WAIT_MS",
                inserts.peak_events_per_second, inserts.inserts_per_second
            ),
        )]
    }
}

/// `ReplacingMergeTree` collapses duplicates within a shard only, so every copy
/// of an event must hash to the same shard.
struct ShardKey;
impl Check for ShardKey {
    fn id(&self) -> &'static str {
        "clickhouse.shard_key"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let key: String = ctx
            .model
            .clickhouse
            .shard_key
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let ok = ["cityHash64", "sipHash64", "xxHash64", "farmHash64"]
            .iter()
            .any(|f| key == format!("{f}(event_id)"));
        if ok {
            return Vec::new();
        }
        vec![breach(
            self.id(),
            format!(
                "shard key `{}` is not a hash of event_id alone: a redelivered event must land on \
                 the shard that already holds it, or ReplacingMergeTree never sees the duplicate \
                 (rand() splits copies; chain makes a hot shard of the busiest chain)",
                ctx.model.clickhouse.shard_key
            ),
        )]
    }
}

struct KafkaThroughput;
impl Check for KafkaThroughput {
    fn id(&self) -> &'static str {
        "kafka.deployed_partitions"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let deployed = ctx.model.kafka.deployed_partitions;
        ctx.plan
            .kafka
            .topics
            .iter()
            .filter(|t| t.partitions_for_throughput > deployed)
            .map(|t| {
                breach(
                    self.id(),
                    format!(
                        "{} needs {} partitions for its horizon peak of {:.0} B/s; {deployed} are \
                         deployed, and growing the count later re-maps every business key",
                        t.event_type, t.partitions_for_throughput, t.peak_bytes_per_second
                    ),
                )
            })
            .collect()
    }
}

struct KafkaReplicas;
impl Check for KafkaReplicas {
    fn id(&self) -> &'static str {
        "kafka.max_partition_replicas_per_broker"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let k = &ctx.plan.kafka;
        let limit = ctx.model.kafka.max_partition_replicas_per_broker as f64;
        if k.partition_replicas_per_broker <= limit {
            return Vec::new();
        }
        vec![breach(
            self.id(),
            format!(
                "{:.0} partition replicas per broker, over {limit}",
                k.partition_replicas_per_broker
            ),
        )]
    }
}

/// Chain-keyed topics can only spread across the partitions chain keys occupy.
struct ChainPlacement;
impl Check for ChainPlacement {
    fn id(&self) -> &'static str {
        "kafka.chain_placement"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let k = &ctx.plan.kafka;
        if k.chain_parallelism as usize >= k.chain_partitions.len() {
            return Vec::new();
        }
        let chain_keyed = k.topics.iter().filter(|t| t.key == KeyKind::Chain).count();
        vec![advisory(
            self.id(),
            format!(
                "at {} partitions the chain keys land on {:?}: {} chains share {} partition(s) on \
                 the {chain_keyed} chain-keyed topics — give the unslotted chain a \
                 `Chain::partition_slot`",
                ctx.model.kafka.deployed_partitions,
                k.chain_partitions,
                k.chain_partitions.len(),
                k.chain_parallelism
            ),
        )]
    }
}

struct Shards;
impl Check for Shards {
    fn id(&self) -> &'static str {
        "clickhouse.shards"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let ch = &ctx.model.clickhouse;
        ctx.plan
            .years
            .iter()
            .find(|y| y.shards > 1)
            .map(|first| {
                advisory(
                    self.id(),
                    format!(
                        "one {:.0} GiB node holds the event store until year {}; then it needs {} \
                         shards × {} replicas, distributed by {}",
                        ch.node_disk_gib.get(),
                        first.year,
                        first.shards,
                        ch.replicas,
                        ch.shard_key
                    ),
                )
            })
            .into_iter()
            .collect()
    }
}

struct DeployedVolumes;
impl Check for DeployedVolumes {
    fn id(&self) -> &'static str {
        "deploy.volumes"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let t = &ctx.plan.timeline;
        let mut out = Vec::new();
        if let Some(day) = t.deployed_clickhouse_full_day {
            out.push(advisory(
                self.id(),
                format!(
                    "the deployed {:.0} GiB ClickHouse volume passes its fill ceiling on day {day} — \
                     the base manifest is dev-sized",
                    ctx.model.clickhouse.deployed_pvc_gib.get()
                ),
            ));
        }
        if let Some(day) = t.deployed_kafka_full_day {
            out.push(advisory(
                self.id(),
                format!(
                    "the deployed {:.0} GiB Kafka volume passes its fill ceiling on day {day}",
                    ctx.model.kafka.deployed_pvc_gib.get()
                ),
            ));
        }
        out
    }
}

struct BrokerDisk;
impl Check for BrokerDisk {
    fn id(&self) -> &'static str {
        "kafka.broker_disk_gib"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let k = &ctx.model.kafka;
        let used = ctx.plan.kafka.broker_disk_gib_at_horizon;
        let usable = k.broker_disk_gib.get() * k.max_disk_fill.get();
        if used <= usable {
            return Vec::new();
        }
        let brokers = (used * f64::from(k.brokers) / usable).ceil();
        vec![advisory(
            self.id(),
            format!("{used:.0} GiB per broker at the horizon, over {usable:.0} usable — plan {brokers:.0} brokers or larger disks"),
        )]
    }
}

struct RetentionHeadroom;
impl Check for RetentionHeadroom {
    fn id(&self) -> &'static str {
        "retention.window"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        ctx.plan
            .tables
            .iter()
            .find(|t| t.id == "event-store/events")
            .and_then(|t| t.max_window_for_insert_limit)
            .map(|days| {
                advisory(
                    self.id(),
                    format!(
                        "PARTITION BY {} keeps a restore of events under the insert-block limit \
                         for evidence windows up to {days} days; a longer retention policy (EU \
                         member states may require ten years) needs a coarser key first",
                        ctx.plan.events_key
                    ),
                )
            })
            .into_iter()
            .collect()
    }
}

struct Assumptions;
impl Check for Assumptions {
    fn id(&self) -> &'static str {
        "model.assumed"
    }
    fn judge(&self, ctx: &Context<'_>) -> Vec<Finding> {
        let assumed: Vec<&str> = ctx
            .model
            .estimates()
            .into_iter()
            .filter(|(_, e)| e.is_assumed())
            .map(|(name, _)| name)
            .collect();
        if assumed.is_empty() {
            return Vec::new();
        }
        vec![advisory(
            self.id(),
            format!(
                "still assumed, not measured: {} — docs/runbooks/capacity-plan.md §4",
                assumed.join(", ")
            ),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_ids_are_unique() {
        let mut ids: Vec<&str> = registry().iter().map(|c| c.id()).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before);
    }
}
