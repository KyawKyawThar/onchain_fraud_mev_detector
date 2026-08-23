//! The finding-finality changelog (§15, §24, Sprint 17 task 3 — production
//! hardening): durability for [`crate::finality::FindingFinalityTracker`],
//! the same gap-closing move `crate::changelog` already made for
//! [`crate::buffer::CandidateLegBuffer`] in task 2's hardening pass. Without
//! this, a restart silently loses which findings were still awaiting
//! finality — a real `BlockReverted` for one of them afterwards would
//! retract nothing (the accepted limitation this module's first cut
//! documented). Mirrors `crate::changelog`'s shape closely; kept in its own
//! module rather than folded into `finality.rs` for the same reason the leg
//! buffer's durability lives apart from the buffer itself — one module, one
//! job (see this crate's file-size-discipline convention).
//!
//! ## Event-sourced, not state-sourced
//!
//! Each entry journals a **call that was made to the tracker**, not a
//! snapshot of resulting state: [`FindingChangelogEntry::Recorded`] mirrors
//! [`crate::finality::FindingFinalityTracker::record_finding`]'s inputs,
//! `LegFinalized`/`LegReverted` mirror `on_block_finalized`/
//! `on_block_reverted`'s. [`replay`] reconstructs state by folding the same
//! pure functions over the journaled calls in order — ordinary event
//! sourcing, not a bespoke replay format. This is why there is no `Evicted`
//! entry: a retention/capacity eviction is a **deterministic function** of
//! `(retention, capacity, the `Recorded` calls' timestamps)`, so replaying
//! just the calls and running eviction once at the end (mirrors
//! [`crate::actor::CorrelationActor::new_with_seed`]'s seed-then-evict-once
//! shape) reproduces it without journaling a redundant derived fact.
//!
//! ## Ordering
//!
//! One partition, deliberately, same reasoning as
//! [`crate::changelog::CHANGELOG_TOPIC`]: a `LegFinalized`/`LegReverted` for
//! a leg must always replay *after* the `Recorded` that introduced it, and
//! entries can originate from many concurrent bridge/pair actors plus the
//! one [`crate::finality::FinalityConsumer`] — a single partition gives that
//! total order for free.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication};
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::error::RDKafkaErrorCode;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::{ClientConfig, Message, Offset, TopicPartitionList};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::finality::FindingFinalityTracker;
use crate::leg::BridgeOrPair;
use events::primitives::{Chain, CrossChainFindingId};

/// A leg's identity for finality tracking: which chain, which block hash.
/// Not the fuller [`events::cross_chain::CrossChainLegRef`] (no tx needed
/// here — finality/reorg is decided at the block level).
pub type LegKey = (Chain, alloy_primitives::B256);

/// Which behaviour a tracked finding is — a closed, typed alternative to a
/// bare `&'static str` so the changelog (and [`crate::finality`]'s tracker)
/// have a real serde shape instead of an opaque string. [`Self::as_str`]
/// bridges back to the label this crate's metrics/logs already key on
/// (`crate::metrics::FINDINGS_TOTAL` et al.) — that existing string
/// vocabulary is kept as-is rather than renamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingKind {
    BridgeMev,
    CrossChainMev,
}

impl FindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingKind::BridgeMev => "bridge_mev",
            FindingKind::CrossChainMev => "cross_chain_mev",
        }
    }
}

/// The changelog-append seam — mirrors `crate::changelog::ChangelogSink`
/// exactly (a trait, not a bare writer type, so tests substitute an
/// in-memory double instead of a live broker).
#[async_trait]
pub trait FindingChangelogSink: Send + Sync {
    async fn append(
        &self,
        entry: &FindingChangelogEntry,
        backoff: Duration,
        shutdown: &CancellationToken,
    );
}

/// Topic for this crate's finding-finality changelog — outside `mev.events.*`,
/// same reasoning as [`crate::changelog::CHANGELOG_TOPIC`].
pub const FINDING_CHANGELOG_TOPIC: &str = "cross-chain-correlator.finding-changelog";

/// Default retention: comfortably longer than
/// [`crate::finality::DEFAULT_FINDING_RETENTION_SECS`] (1h) so replay can
/// always still see the `Recorded` fact for anything that would legitimately
/// still be tracked — retention here *must* exceed the finding-retention
/// window it journals, or replay can silently miss a still-live finding (see
/// [`crate::config::Config::from_env`]'s boot-time check).
pub const DEFAULT_FINDING_CHANGELOG_RETENTION_MS: i64 = 4 * 60 * 60 * 1_000;

/// Default deadline for [`replay`] — same "partial warm start beats
/// blocking boot indefinitely" reasoning as
/// [`crate::changelog::DEFAULT_REPLAY_TIMEOUT`].
pub const DEFAULT_REPLAY_TIMEOUT: Duration = Duration::from_secs(30);

const ADMIN_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// One durable fact about a call made to
/// [`crate::finality::FindingFinalityTracker`] — see the module docs for why
/// this journals calls, not snapshots.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum FindingChangelogEntry {
    Recorded {
        finding_id: CrossChainFindingId,
        bridge_or_pair: BridgeOrPair,
        kind: FindingKind,
        legs: Vec<LegKey>,
        recorded_at: DateTime<Utc>,
    },
    LegFinalized {
        chain: Chain,
        hash: alloy_primitives::B256,
    },
    LegReverted {
        chain: Chain,
        hash: alloy_primitives::B256,
    },
}

/// Appends [`FindingChangelogEntry`]s — mirrors
/// `crate::changelog::ChangelogWriter` exactly, one Kafka producer shared
/// across the whole process (every bridge/pair actor plus the finality
/// consumer, via `SharedFindingFinalityTracker`).
pub struct FindingChangelogWriter {
    producer: FutureProducer,
}

impl FindingChangelogWriter {
    pub fn new(brokers: &str) -> Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .set("acks", "all")
            .set("enable.idempotence", "true")
            .set("message.timeout.ms", "30000")
            .create()
            .context("building the finding-changelog Kafka producer")?;
        Ok(Self { producer })
    }

    /// Provision [`FINDING_CHANGELOG_TOPIC`] if it doesn't already exist —
    /// idempotent, mirrors `ChangelogWriter::ensure_topic`.
    pub async fn ensure_topic(brokers: &str, replication: i32, retention_ms: i64) -> Result<()> {
        let admin: AdminClient<_> = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .create()
            .context("creating a Kafka admin client for the finding changelog")?;
        let retention = retention_ms.to_string();
        let new_topic = NewTopic::new(
            FINDING_CHANGELOG_TOPIC,
            1,
            TopicReplication::Fixed(replication),
        )
        .set("retention.ms", &retention)
        .set("cleanup.policy", "delete");
        let opts = AdminOptions::new()
            .request_timeout(Some(ADMIN_TIMEOUT))
            .operation_timeout(Some(ADMIN_TIMEOUT));
        let results = admin
            .create_topics(&[new_topic], &opts)
            .await
            .context("requesting finding-changelog topic creation")?;
        for result in results {
            match result {
                Ok(name) => tracing::info!(topic = %name, "provisioned finding-changelog topic"),
                Err((name, RDKafkaErrorCode::TopicAlreadyExists)) => {
                    tracing::debug!(topic = %name, "finding-changelog topic already exists; left as-is");
                }
                Err((name, code)) => {
                    anyhow::bail!("failed to provision finding-changelog topic {name}: {code:?}");
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl FindingChangelogSink for FindingChangelogWriter {
    /// Append one entry, retrying transient publish failures until it lands
    /// or `shutdown` fires — same durability discipline as
    /// `ChangelogWriter::append` and `event_bus::publish_resilient`.
    async fn append(
        &self,
        entry: &FindingChangelogEntry,
        backoff: Duration,
        shutdown: &CancellationToken,
    ) {
        // Keyed by finding id where the entry names one, else by leg — good
        // enough partition-key hygiene even though the topic is single-
        // partition today (see module docs on why ordering doesn't need
        // more than one).
        let key = match entry {
            FindingChangelogEntry::Recorded { finding_id, .. } => finding_id.to_string(),
            FindingChangelogEntry::LegFinalized { chain, hash }
            | FindingChangelogEntry::LegReverted { chain, hash } => {
                format!("{}:{hash:#x}", chain.id())
            }
        };
        let payload = match serde_json::to_vec(entry) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "failed to encode a finding-changelog entry; it will not be durable"
                );
                crate::metrics::record_changelog_error("finding_encode");
                return;
            }
        };
        loop {
            let record = FutureRecord::to(FINDING_CHANGELOG_TOPIC)
                .key(&key)
                .payload(&payload);
            match self.producer.send(record, SEND_TIMEOUT).await {
                Ok(_) => return,
                Err((err, _)) => {
                    tracing::warn!(error = %err, "finding-changelog append failed; retrying");
                    crate::metrics::record_changelog_error("finding_publish_retry");
                    tokio::select! {
                        biased;
                        () = shutdown.cancelled() => {
                            tracing::error!(
                                "shutdown during finding-changelog append retry; entry not durable"
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

/// An in-memory [`FindingChangelogSink`] recording every entry — the
/// finding-changelog counterpart to `crate::changelog::RecordingChangelogWriter`.
#[cfg(test)]
#[derive(Default)]
pub struct RecordingFindingChangelogWriter {
    entries: std::sync::Mutex<Vec<FindingChangelogEntry>>,
}

#[cfg(test)]
impl RecordingFindingChangelogWriter {
    pub fn entries(&self) -> Vec<FindingChangelogEntry> {
        self.entries.lock().unwrap().clone()
    }
}

#[cfg(test)]
#[async_trait]
impl FindingChangelogSink for RecordingFindingChangelogWriter {
    async fn append(
        &self,
        entry: &FindingChangelogEntry,
        _backoff: Duration,
        _shutdown: &CancellationToken,
    ) {
        self.entries.lock().unwrap().push(entry.clone());
    }
}

/// Fold one journaled entry into `tracker` — the pure replay step, split out
/// so both [`replay`] and its unit tests can drive it without Kafka. Uses
/// [`FindingFinalityTracker::insert_raw`] (not `record_finding`) for
/// `Recorded`, so eviction isn't repeatedly (and redundantly) evaluated
/// mid-replay against a historical `now` — see the module docs.
fn apply_entry(tracker: &mut FindingFinalityTracker, entry: FindingChangelogEntry) {
    match entry {
        FindingChangelogEntry::Recorded {
            finding_id,
            bridge_or_pair,
            kind,
            legs,
            recorded_at,
        } => {
            tracker.insert_raw(finding_id, bridge_or_pair, kind, legs, recorded_at);
        }
        FindingChangelogEntry::LegFinalized { chain, hash } => {
            tracker.on_block_finalized(chain, hash);
        }
        FindingChangelogEntry::LegReverted { chain, hash } => {
            tracker.on_block_reverted(chain, hash);
        }
    }
}

/// Replay [`FINDING_CHANGELOG_TOPIC`] into a fresh
/// [`FindingFinalityTracker`], reconstructing exactly which findings were
/// still awaiting finality as of the last durably-logged call — the
/// finding-tracker counterpart to `crate::changelog::replay`. Best-effort
/// against `timeout`, same "partial warm start beats blocking boot
/// indefinitely" stance. Runs eviction exactly once, at the end, against
/// real "now" (mirrors `CorrelationActor::new_with_seed`'s seed-then-evict
/// shape) rather than per-entry against historical timestamps.
pub async fn replay(
    brokers: &str,
    consumer_group_prefix: &str,
    replica_index: u32,
    timeout: Duration,
    retention: chrono::TimeDelta,
    capacity: usize,
) -> Result<FindingFinalityTracker> {
    let brokers = brokers.to_owned();
    let group_id = format!("{consumer_group_prefix}-r{replica_index}-finding-changelog-replay");

    let (consumer, high_watermarks) = tokio::task::spawn_blocking(
        move || -> Result<(StreamConsumer, std::collections::HashMap<i32, i64>)> {
            let consumer: StreamConsumer = ClientConfig::new()
                .set("bootstrap.servers", &brokers)
                .set("group.id", &group_id)
                .set("enable.auto.commit", "false")
                .create()
                .context("building the finding-changelog replay consumer")?;

            let metadata = consumer
                .fetch_metadata(Some(FINDING_CHANGELOG_TOPIC), ADMIN_TIMEOUT)
                .context("fetching finding-changelog topic metadata")?;
            let topic_metadata = metadata
                .topics()
                .first()
                .context("finding-changelog topic metadata came back empty")?;

            let mut tpl = TopicPartitionList::new();
            let mut high_watermarks = std::collections::HashMap::new();
            for partition_metadata in topic_metadata.partitions() {
                let partition = partition_metadata.id();
                tpl.add_partition_offset(FINDING_CHANGELOG_TOPIC, partition, Offset::Beginning)
                    .context("assigning a finding-changelog partition")?;
                let (_low, high) = consumer
                    .fetch_watermarks(FINDING_CHANGELOG_TOPIC, partition, ADMIN_TIMEOUT)
                    .context("fetching finding-changelog watermarks")?;
                high_watermarks.insert(partition, high);
            }
            consumer
                .assign(&tpl)
                .context("assigning finding-changelog partitions for replay")?;

            Ok((consumer, high_watermarks))
        },
    )
    .await
    .context("finding-changelog replay setup task panicked")??;

    let mut tracker = FindingFinalityTracker::new(retention, capacity);
    let mut current_offsets: std::collections::HashMap<i32, i64> = std::collections::HashMap::new();
    let mut applied = 0usize;
    let deadline = tokio::time::Instant::now() + timeout;

    let is_caught_up = |current: &std::collections::HashMap<i32, i64>| {
        high_watermarks
            .iter()
            .all(|(p, &high)| high == 0 || current.get(p).copied().unwrap_or(0) >= high)
    };

    while !is_caught_up(&current_offsets) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            tracing::warn!(
                applied,
                "finding-changelog replay hit its timeout before catching up to every \
                 partition's watermark; continuing boot with a partial warm start"
            );
            break;
        }
        match tokio::time::timeout(remaining.min(POLL_INTERVAL), consumer.recv()).await {
            Ok(Ok(message)) => {
                current_offsets.insert(message.partition(), message.offset() + 1);
                if let Some(payload) = message.payload() {
                    match serde_json::from_slice::<FindingChangelogEntry>(payload) {
                        Ok(entry) => {
                            apply_entry(&mut tracker, entry);
                            applied += 1;
                        }
                        Err(err) => tracing::warn!(
                            error = %err,
                            "skipping an unreadable finding-changelog entry during replay"
                        ),
                    }
                }
            }
            Ok(Err(err)) => {
                tracing::warn!(error = %err, "finding-changelog replay read error; stopping replay early");
                break;
            }
            Err(_elapsed) => {}
        }
    }

    // Eviction runs once, against real "now", after every historical entry
    // is applied — see this fn's docs.
    let evicted = tracker.evict_now();

    tracing::info!(
        entries_applied = applied,
        findings_restored = tracker.len(),
        findings_aged_out_on_restore = evicted.len(),
        "finding-changelog replay complete"
    );
    Ok(tracker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finality::FindingFinalityTracker;
    use alloy_primitives::B256;
    use chrono::TimeDelta;

    fn bridge() -> BridgeOrPair {
        BridgeOrPair("usdc-eth-base".to_owned())
    }

    fn leg(chain: Chain, tag: u8) -> LegKey {
        (chain, B256::repeat_byte(tag))
    }

    #[test]
    fn replaying_recorded_then_leg_reverted_retracts_the_finding() {
        let mut tracker = FindingFinalityTracker::new(TimeDelta::hours(1), 100);
        let id = CrossChainFindingId::new();
        let now = Utc::now();

        apply_entry(
            &mut tracker,
            FindingChangelogEntry::Recorded {
                finding_id: id,
                bridge_or_pair: bridge(),
                kind: FindingKind::BridgeMev,
                legs: vec![leg(Chain::ETHEREUM, 1), leg(Chain::BASE, 2)],
                recorded_at: now,
            },
        );
        assert_eq!(tracker.len(), 1);

        apply_entry(
            &mut tracker,
            FindingChangelogEntry::LegReverted {
                chain: Chain::ETHEREUM,
                hash: B256::repeat_byte(1),
            },
        );
        assert!(
            tracker.is_empty(),
            "the replayed revert retracts the finding"
        );
    }

    #[test]
    fn replaying_recorded_then_both_legs_finalized_drops_it_as_fully_final() {
        let mut tracker = FindingFinalityTracker::new(TimeDelta::hours(1), 100);
        let id = CrossChainFindingId::new();
        let now = Utc::now();

        apply_entry(
            &mut tracker,
            FindingChangelogEntry::Recorded {
                finding_id: id,
                bridge_or_pair: bridge(),
                kind: FindingKind::CrossChainMev,
                legs: vec![leg(Chain::ETHEREUM, 1), leg(Chain::BASE, 2)],
                recorded_at: now,
            },
        );
        apply_entry(
            &mut tracker,
            FindingChangelogEntry::LegFinalized {
                chain: Chain::ETHEREUM,
                hash: B256::repeat_byte(1),
            },
        );
        assert_eq!(tracker.len(), 1, "still waiting on the other leg");
        apply_entry(
            &mut tracker,
            FindingChangelogEntry::LegFinalized {
                chain: Chain::BASE,
                hash: B256::repeat_byte(2),
            },
        );
        assert!(tracker.is_empty(), "fully finalized, no longer tracked");
    }

    #[test]
    fn a_stale_recorded_entry_is_pruned_by_the_post_replay_eviction() {
        // `insert_raw` (via `apply_entry`) never evicts mid-replay — the
        // module docs' "eviction runs once, at the end" design. A finding
        // recorded long before "now" must still be pruned once that final
        // sweep runs.
        let mut tracker = FindingFinalityTracker::new(TimeDelta::minutes(10), 100);
        let id = CrossChainFindingId::new();
        let old = Utc::now() - TimeDelta::hours(2);

        apply_entry(
            &mut tracker,
            FindingChangelogEntry::Recorded {
                finding_id: id,
                bridge_or_pair: bridge(),
                kind: FindingKind::BridgeMev,
                legs: vec![leg(Chain::ETHEREUM, 1)],
                recorded_at: old,
            },
        );
        assert_eq!(tracker.len(), 1, "insert_raw does not evict on its own");

        let evicted = tracker.evict_now();
        assert_eq!(evicted.len(), 1);
        assert!(tracker.is_empty());
    }

    #[test]
    fn changelog_entries_round_trip_through_json() {
        let recorded = FindingChangelogEntry::Recorded {
            finding_id: CrossChainFindingId::new(),
            bridge_or_pair: bridge(),
            kind: FindingKind::BridgeMev,
            legs: vec![leg(Chain::ETHEREUM, 1)],
            recorded_at: Utc::now(),
        };
        let json = serde_json::to_vec(&recorded).unwrap();
        assert_eq!(
            serde_json::from_slice::<FindingChangelogEntry>(&json).unwrap(),
            recorded
        );

        let reverted = FindingChangelogEntry::LegReverted {
            chain: Chain::BASE,
            hash: B256::repeat_byte(9),
        };
        let json = serde_json::to_vec(&reverted).unwrap();
        assert_eq!(
            serde_json::from_slice::<FindingChangelogEntry>(&json).unwrap(),
            reverted
        );
    }

    #[test]
    fn finding_kind_as_str_matches_the_existing_metric_label_vocabulary() {
        assert_eq!(FindingKind::BridgeMev.as_str(), "bridge_mev");
        assert_eq!(FindingKind::CrossChainMev.as_str(), "cross_chain_mev");
    }

    #[tokio::test]
    async fn recording_writer_records_every_entry_in_order() {
        let writer = RecordingFindingChangelogWriter::default();
        let a = FindingChangelogEntry::LegFinalized {
            chain: Chain::ETHEREUM,
            hash: B256::repeat_byte(1),
        };
        let b = FindingChangelogEntry::LegReverted {
            chain: Chain::BASE,
            hash: B256::repeat_byte(2),
        };
        writer
            .append(&a, Duration::from_millis(1), &CancellationToken::new())
            .await;
        writer
            .append(&b, Duration::from_millis(1), &CancellationToken::new())
            .await;
        assert_eq!(writer.entries(), vec![a, b]);
    }
}
