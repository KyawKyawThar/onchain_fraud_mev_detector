//! The leg-buffer changelog (§17, §24 — production hardening): every
//! [`CandidateLeg`] a [`crate::actor::CorrelationActor`] buffers or removes
//! is durably appended here *before* that mutation is treated as complete,
//! so a restart can replay this topic and rebuild the exact set of in-flight
//! (unmatched) legs it held before going down, instead of silently losing
//! whatever was mid-window at the moment of the crash/redeploy — the gap
//! flagged when task 2 shipped: "a restart can silently drop up to
//! `leg_window` seconds of in-flight correlations."
//!
//! This is event-sourcing applied narrowly: [`CandidateLegBuffer`] is the
//! *read model*, this topic is the *log*. Deliberately **not** an
//! [`events::DomainEvent`] — it is this crate's own internal implementation
//! state, not a platform-wide business fact, so it stays off the shared
//! `mev.events.*` namespace/schema the event-store ingests (mirrors why
//! `event_bus::dlq`'s dead-letter topic lives outside that namespace too).
//!
//! Kept deliberately simpler than a real changelog-compacted state store
//! (Kafka Streams' RocksDB+changelog): one **time-bounded-retention** topic
//! (not log-compacted), replayed in full at boot. Legs live for at most
//! `leg_window` (minutes), so a retention window a little longer than that
//! self-prunes the topic without needing compaction machinery — replay cost
//! stays proportional to recent traffic, not to the service's whole
//! lifetime. One partition, deliberately: `Buffered` must always be applied
//! before its matching `Removed` during replay, and a single partition gives
//! that ordering for free (Kafka's per-partition order) without having to
//! reason about whether every entry for one bridge/pair lands on the same
//! partition of a multi-partition topic.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::error::RDKafkaErrorCode;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::{ClientConfig, Message, Offset, TopicPartitionList};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::leg::{BridgeOrPair, CandidateLeg};

/// The changelog-append seam — a trait (not a bare `ChangelogWriter` type)
/// for the same reason `event_bus::EventSink` is one: it lets
/// [`crate::actor::CorrelationActor::run`]'s tests substitute a fast,
/// in-memory double ([`RecordingChangelogWriter`], test-only) instead of
/// exercising a real Kafka producer, mirroring `event_bus::test_util::RecordingSink`.
#[async_trait]
pub trait ChangelogSink: Send + Sync {
    async fn append(&self, entry: &ChangelogEntry, backoff: Duration, shutdown: &CancellationToken);
}

/// Topic for this crate's internal changelog — outside `mev.events.*`, same
/// reasoning as `event_bus::dlq::DLQ_TOPIC_PREFIX`.
pub const CHANGELOG_TOPIC: &str = "cross-chain-correlator.leg-changelog";

/// Default retention: an hour comfortably covers any sane `leg_window`
/// (default 10 minutes) with room to spare for a slow replay/boot.
pub const DEFAULT_RETENTION_MS: i64 = 60 * 60 * 1_000;

/// Default deadline for [`replay`] — generous for the traffic this topic is
/// ever expected to carry (bounded by `leg_window` * total buffer capacity
/// across every bridge/pair), while still bounding how long boot can stall.
pub const DEFAULT_REPLAY_TIMEOUT: Duration = Duration::from_secs(30);

const ADMIN_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a single `poll` waits for the next replay record before
/// re-checking the overall deadline/catch-up condition.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// One durable fact about a buffer mutation (§24): a leg entered a
/// bridge/pair's window, or one left it (matched, aged out, or dropped by
/// the capacity backstop) — the two operations
/// [`crate::buffer::CandidateLegBuffer`] supports. Replaying every entry, in
/// order, reconstructs every bridge/pair's buffer exactly as of the last
/// entry durably written.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum ChangelogEntry {
    Buffered(CandidateLeg),
    Removed {
        bridge_or_pair: BridgeOrPair,
        tx: alloy_primitives::B256,
    },
}

impl ChangelogEntry {
    fn bridge_or_pair(&self) -> &BridgeOrPair {
        match self {
            ChangelogEntry::Buffered(leg) => &leg.bridge_or_pair,
            ChangelogEntry::Removed { bridge_or_pair, .. } => bridge_or_pair,
        }
    }
}

/// Appends [`ChangelogEntry`]s, sharing one Kafka producer across every
/// correlation actor the same way `event_bus::KafkaEventSink` is shared for
/// live findings.
pub struct ChangelogWriter {
    producer: FutureProducer,
}

impl ChangelogWriter {
    pub fn new(brokers: &str) -> Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("acks", "all")
            .set("enable.idempotence", "true")
            .set("message.timeout.ms", "30000")
            .create()
            .context("building the leg-changelog Kafka producer")?;
        Ok(Self { producer })
    }

    /// Provision [`CHANGELOG_TOPIC`] if it doesn't already exist — idempotent,
    /// mirrors `event_bus::dlq::DeadLetterQueue::ensure`'s admin-client
    /// pattern — with the time-bounded, non-compacted retention module docs
    /// describe.
    pub async fn ensure_topic(brokers: &str, replication: i32, retention_ms: i64) -> Result<()> {
        let admin: AdminClient<_> = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .create()
            .context("creating a Kafka admin client for the leg changelog")?;
        let retention = retention_ms.to_string();
        let new_topic = NewTopic::new(CHANGELOG_TOPIC, 1, TopicReplication::Fixed(replication))
            .set("retention.ms", &retention)
            .set("cleanup.policy", "delete");
        let opts = AdminOptions::new()
            .request_timeout(Some(ADMIN_TIMEOUT))
            .operation_timeout(Some(ADMIN_TIMEOUT));
        let results = admin
            .create_topics(&[new_topic], &opts)
            .await
            .context("requesting leg-changelog topic creation")?;
        for result in results {
            match result {
                Ok(name) => tracing::info!(topic = %name, "provisioned leg-changelog topic"),
                Err((name, RDKafkaErrorCode::TopicAlreadyExists)) => {
                    tracing::debug!(topic = %name, "leg-changelog topic already exists; left as-is");
                }
                Err((name, code)) => {
                    anyhow::bail!("failed to provision leg-changelog topic {name}: {code:?}");
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ChangelogSink for ChangelogWriter {
    /// Append one entry, retrying transient publish failures until it lands
    /// or `shutdown` fires — the same durability discipline
    /// `event_bus::publish_resilient` gives domain events, so a completed
    /// join is never published upstream on the strength of a buffer
    /// mutation this crate can't actually replay after a crash. A
    /// (de)serialize failure is a local bug, not a transport one — logged
    /// and counted, not retried, since retrying can't fix it.
    async fn append(
        &self,
        entry: &ChangelogEntry,
        backoff: Duration,
        shutdown: &CancellationToken,
    ) {
        let key = entry.bridge_or_pair().to_string();
        let payload = match serde_json::to_vec(entry) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "failed to encode a leg-changelog entry; it will not be durable"
                );
                crate::metrics::record_changelog_error("encode");
                return;
            }
        };
        loop {
            let record = FutureRecord::to(CHANGELOG_TOPIC)
                .key(&key)
                .payload(&payload);
            match self.producer.send(record, SEND_TIMEOUT).await {
                Ok(_) => return,
                Err((err, _)) => {
                    tracing::warn!(error = %err, "leg-changelog append failed; retrying");
                    crate::metrics::record_changelog_error("publish_retry");
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => {
                            tracing::error!(
                                "shutdown during leg-changelog append retry; entry not durable"
                            );
                            return;
                        }
                        () = tokio::time::sleep(backoff) => {}
                    }
                }
            }
        }
    }
}

/// An in-memory [`ChangelogSink`] that records every entry instead of
/// touching Kafka — the changelog counterpart to
/// `event_bus::test_util::RecordingSink`, for [`crate::actor`]'s tests to
/// assert on *what* a `CorrelationActor` decided to log without needing a
/// live broker.
#[cfg(test)]
#[derive(Default)]
pub struct RecordingChangelogWriter {
    entries: std::sync::Mutex<Vec<ChangelogEntry>>,
}

#[cfg(test)]
impl RecordingChangelogWriter {
    pub fn entries(&self) -> Vec<ChangelogEntry> {
        self.entries.lock().unwrap().clone()
    }
}

#[cfg(test)]
#[async_trait]
impl ChangelogSink for RecordingChangelogWriter {
    async fn append(
        &self,
        entry: &ChangelogEntry,
        _backoff: Duration,
        _shutdown: &CancellationToken,
    ) {
        self.entries.lock().unwrap().push(entry.clone());
    }
}

/// Replay [`CHANGELOG_TOPIC`] from the start of its retention window up to
/// "now" (every partition's high watermark at the moment replay starts),
/// reconstructing every bridge/pair's set of legs as of the last time this
/// process (or a peer) durably logged a mutation. Best-effort: a replay that
/// can't finish within `timeout` logs a warning and returns whatever it
/// managed rather than blocking boot indefinitely — a partial warm start is
/// strictly better than none, and this was always going to be lossy across
/// an outage longer than the topic's retention (see module docs).
pub async fn replay(
    brokers: &str,
    consumer_group_prefix: &str,
    replica_index: u32,
    timeout: Duration,
) -> Result<HashMap<BridgeOrPair, Vec<CandidateLeg>>> {
    let brokers = brokers.to_owned();
    let group_id = format!("{consumer_group_prefix}-r{replica_index}-changelog-replay");

    // The metadata/watermark round-trips are synchronous rdkafka calls;
    // running them (and building the consumer) on a blocking thread keeps
    // this boot-time, one-shot setup from stalling the async runtime's
    // worker threads — other boot tasks (the health-check server) are
    // already running by this point.
    let (consumer, high_watermarks) =
        tokio::task::spawn_blocking(move || -> Result<(StreamConsumer, HashMap<i32, i64>)> {
            let consumer: StreamConsumer = ClientConfig::new()
                .set("bootstrap.servers", &brokers)
                .set("group.id", &group_id)
                .set("enable.auto.commit", "false")
                .create()
                .context("building the leg-changelog replay consumer")?;

            let metadata = consumer
                .fetch_metadata(Some(CHANGELOG_TOPIC), ADMIN_TIMEOUT)
                .context("fetching leg-changelog topic metadata")?;
            let topic_metadata = metadata
                .topics()
                .first()
                .context("leg-changelog topic metadata came back empty")?;

            let mut tpl = TopicPartitionList::new();
            let mut high_watermarks = HashMap::new();
            for partition_metadata in topic_metadata.partitions() {
                let partition = partition_metadata.id();
                tpl.add_partition_offset(CHANGELOG_TOPIC, partition, Offset::Beginning)
                    .context("assigning a leg-changelog partition")?;
                let (_low, high) = consumer
                    .fetch_watermarks(CHANGELOG_TOPIC, partition, ADMIN_TIMEOUT)
                    .context("fetching leg-changelog watermarks")?;
                high_watermarks.insert(partition, high);
            }
            consumer
                .assign(&tpl)
                .context("assigning leg-changelog partitions for replay")?;

            Ok((consumer, high_watermarks))
        })
        .await
        .context("leg-changelog replay setup task panicked")??;

    let mut state: HashMap<BridgeOrPair, Vec<CandidateLeg>> = HashMap::new();
    let mut current_offsets: HashMap<i32, i64> = HashMap::new();
    let mut applied = 0usize;
    let deadline = tokio::time::Instant::now() + timeout;

    let is_caught_up = |current: &HashMap<i32, i64>| {
        high_watermarks
            .iter()
            .all(|(p, &high)| high == 0 || current.get(p).copied().unwrap_or(0) >= high)
    };

    while !is_caught_up(&current_offsets) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            tracing::warn!(
                applied,
                "leg-changelog replay hit its timeout before catching up to every \
                 partition's watermark; continuing boot with a partial warm start"
            );
            break;
        }
        match tokio::time::timeout(remaining.min(POLL_INTERVAL), consumer.recv()).await {
            Ok(Ok(message)) => {
                current_offsets.insert(message.partition(), message.offset() + 1);
                if let Some(payload) = message.payload() {
                    match serde_json::from_slice::<ChangelogEntry>(payload) {
                        Ok(entry) => {
                            apply_entry(&mut state, entry);
                            applied += 1;
                        }
                        Err(err) => tracing::warn!(
                            error = %err,
                            "skipping an unreadable leg-changelog entry during replay"
                        ),
                    }
                }
            }
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "leg-changelog replay read error; stopping replay early");
                break;
            }
            Err(_elapsed) => {
                // No record within the poll interval — either genuinely
                // caught up (re-checked at the top of the loop) or the topic
                // is briefly idle; keep polling until the deadline either way.
            }
        }
    }

    tracing::info!(
        bridges_or_pairs = state.len(),
        entries_applied = applied,
        "leg-changelog replay complete"
    );
    Ok(state)
}

fn apply_entry(state: &mut HashMap<BridgeOrPair, Vec<CandidateLeg>>, entry: ChangelogEntry) {
    match entry {
        ChangelogEntry::Buffered(leg) => {
            state
                .entry(leg.bridge_or_pair.clone())
                .or_default()
                .push(leg);
        }
        ChangelogEntry::Removed { bridge_or_pair, tx } => {
            if let Some(legs) = state.get_mut(&bridge_or_pair) {
                legs.retain(|leg| leg.tx != tx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};
    use chrono::Utc;
    use events::primitives::{BlockRef, Chain, Confidence};

    fn bridge() -> BridgeOrPair {
        BridgeOrPair("usdc-eth-base".to_owned())
    }

    fn a_leg(tag: u8) -> CandidateLeg {
        CandidateLeg {
            chain: Chain::ETHEREUM,
            block: BlockRef::new(1, B256::repeat_byte(tag)),
            tx: B256::repeat_byte(tag),
            kind: crate::leg::LegKind::LargeSwap,
            bridge_or_pair: bridge(),
            correlation_key: Address::repeat_byte(tag),
            observed_at: Utc::now(),
            confidence: Confidence::new(0.9),
            impact_usd: None,
        }
    }

    #[test]
    fn buffered_then_removed_nets_out_to_absent() {
        let mut state = HashMap::new();
        apply_entry(&mut state, ChangelogEntry::Buffered(a_leg(1)));
        apply_entry(
            &mut state,
            ChangelogEntry::Removed {
                bridge_or_pair: bridge(),
                tx: B256::repeat_byte(1),
            },
        );
        assert!(state.get(&bridge()).unwrap().is_empty());
    }

    #[test]
    fn a_buffered_entry_with_no_matching_removal_survives_replay() {
        let mut state = HashMap::new();
        apply_entry(&mut state, ChangelogEntry::Buffered(a_leg(1)));
        assert_eq!(state[&bridge()].len(), 1);
        assert_eq!(state[&bridge()][0].tx, B256::repeat_byte(1));
    }

    #[test]
    fn removing_an_unknown_bridge_or_pair_is_a_no_op() {
        let mut state = HashMap::new();
        apply_entry(
            &mut state,
            ChangelogEntry::Removed {
                bridge_or_pair: bridge(),
                tx: B256::repeat_byte(1),
            },
        );
        assert!(state.is_empty());
    }

    #[test]
    fn multiple_legs_can_share_a_bridge_or_pair() {
        let mut state = HashMap::new();
        apply_entry(&mut state, ChangelogEntry::Buffered(a_leg(1)));
        apply_entry(&mut state, ChangelogEntry::Buffered(a_leg(2)));
        apply_entry(
            &mut state,
            ChangelogEntry::Removed {
                bridge_or_pair: bridge(),
                tx: B256::repeat_byte(1),
            },
        );
        let remaining = &state[&bridge()];
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].tx, B256::repeat_byte(2));
    }

    #[test]
    fn changelog_entries_round_trip_through_json() {
        let buffered = ChangelogEntry::Buffered(a_leg(1));
        let json = serde_json::to_vec(&buffered).unwrap();
        assert_eq!(
            serde_json::from_slice::<ChangelogEntry>(&json).unwrap(),
            buffered
        );

        let removed = ChangelogEntry::Removed {
            bridge_or_pair: bridge(),
            tx: B256::repeat_byte(2),
        };
        let json = serde_json::to_vec(&removed).unwrap();
        assert_eq!(
            serde_json::from_slice::<ChangelogEntry>(&json).unwrap(),
            removed
        );
    }

    #[test]
    fn bridge_or_pair_extracts_from_either_variant() {
        assert_eq!(
            ChangelogEntry::Buffered(a_leg(1)).bridge_or_pair(),
            &bridge()
        );
        assert_eq!(
            ChangelogEntry::Removed {
                bridge_or_pair: bridge(),
                tx: B256::repeat_byte(1),
            }
            .bridge_or_pair(),
            &bridge()
        );
    }
}
