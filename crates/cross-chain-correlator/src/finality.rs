//! Cross-chain finality + reorg retraction (§15, §24, Sprint 17 task 3): "a
//! finding is only as final as its least-final leg."
//!
//! [`BridgeMevDetected`](events::cross_chain::BridgeMevDetected)/
//! [`CrossChainMevDetected`](events::cross_chain::CrossChainMevDetected) are
//! minted off fast-path facts (Sprint 17 task 2), so — like every fast-path
//! alert — they are provisional until the blocks they cite pass finality
//! depth. Unlike a single-chain alert, a cross-chain finding has *several*
//! blocks to wait on, one per leg, each on its own chain with its own block
//! time and finality depth: the finding stays at risk of retraction until
//! **every** leg is finalized, not just one.
//!
//! [`FindingFinalityTracker`] is the pure core tracking that: which findings
//! are still waiting on which `(chain, block hash)` legs. A finding is
//! recorded the moment [`crate::actor::CorrelationActor::run`] publishes it
//! (see that module), and leaves the tracker one of two ways:
//!
//! - [`FindingFinalityTracker::on_block_finalized`] clears one leg; once a
//!   finding's *last* pending leg finalizes, it is fully final and the
//!   tracker drops it — there is nothing further to retract it (§15 gives
//!   finalized blocks immunity from reorg).
//! - [`FindingFinalityTracker::on_block_reverted`] retracts a finding the
//!   instant *any* of its legs' blocks reverts, without waiting to see
//!   whether the other legs also survive — the finding is only as final as
//!   its least-final leg, so one reverted leg is already enough to withdraw
//!   the whole correlated fact.
//!
//! [`FinalityConsumer`] is the effectful shell: a broadcast `BlockReverted`/
//! `BlockFinalized` consumer (every replica must see every chain's revert,
//! since [`FindingFinalityTracker`]'s state — like
//! [`crate::buffer::CandidateLegBuffer`]'s — is sharded per replica by which
//! bridge/pair actors that replica owns) that drives the tracker and
//! publishes [`events::cross_chain::CrossChainFindingRetracted`] for
//! whatever a revert retracted. Mirrors
//! `simulation::reorg`'s split exactly: [`FindingFinalityTracker`] is this
//! crate's `OrphanedBlocks`, [`FinalityConsumer`] is its `ReorgConsumer`.
//!
//! **Clock-skew tolerance (§24).** Legs are keyed here by `(chain, block
//! hash)`, never compared across chains by block *number* — the same
//! "observation time, not block numbers" discipline
//! [`crate::buffer::CandidateLegBuffer`]'s window already applies to the
//! join. There is no cross-chain block-number arithmetic anywhere in this
//! module for clock skew to corrupt.
//!
//! **Durability ([`crate::finding_changelog`], production hardening).**
//! [`SharedFindingFinalityTracker`] durably journals every call it makes to
//! the pure core *before* applying it, mirroring
//! [`crate::actor::CorrelationActor`]'s changelog-then-publish discipline —
//! see `crate::finding_changelog`'s module docs for the full design. A
//! restart replays that journal (`crate::finding_changelog::replay`) to
//! reconstruct exactly which findings were still awaiting finality, closing
//! the "in-memory only, restart loses tracking" gap this module's first cut
//! left open.
//!
//! **Bounded memory.** [`FindingFinalityTracker`] retains a finding only
//! until every leg finalizes or one reverts — bounded in the ordinary case by
//! how long finality actually takes, not by anything this crate controls. As
//! a backstop against a chain whose `BlockFinalized` stream stalls or never
//! arrives (a misconfigured/broken finality feed), findings are also evicted
//! past a configurable retention window and a hard capacity cap — same
//! "time window plus hard backstop" shape as
//! [`crate::buffer::CandidateLegBuffer`] and
//! `simulation::reorg::OrphanedBlocks`. Eviction is O(log n) via a
//! `BTreeSet` age index ([`FindingFinalityTracker`]'s `by_age`) rather than
//! scanning every tracked finding on every write — findings are rare enough
//! events that this was never a hot path, but the indexed form costs nothing
//! extra to keep correct and scales cleanly if that ever changes.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::B256;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use event_bus::{publish_resilient, run_consumer, EventHandler, EventSink, Handled};
use events::chain::{BlockFinalized, BlockReverted};
use events::cross_chain::CrossChainFindingRetracted;
use events::primitives::{Chain, CrossChainFindingId};
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use rdkafka::ClientConfig;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::finding_changelog::{FindingChangelogEntry, FindingChangelogSink, FindingKind, LegKey};
use crate::leg::BridgeOrPair;

/// Default retention: generous relative to any sane finality depth/time
/// across the chains this deployment monitors (§15's finalization windows
/// are minutes, not hours) — the same "comfortably covers the real window,
/// with room for a slow `BlockFinalized` feed" role
/// `changelog::DEFAULT_RETENTION_MS` plays for the leg buffer.
///
/// [`crate::finding_changelog::DEFAULT_FINDING_CHANGELOG_RETENTION_MS`] must
/// stay comfortably longer than this — see that constant's docs.
pub const DEFAULT_FINDING_RETENTION_SECS: i64 = 3600;

/// Default hard cap on findings retained awaiting finality — the same
/// "backstop, not the everyday limit" role
/// [`crate::buffer::DEFAULT_CANDIDATE_LEG_CAPACITY`] plays; findings are far
/// rarer than legs, so this is smaller.
pub const DEFAULT_FINDING_CAPACITY: usize = 50_000;

/// A finding's identity plus the labels a metric/log needs — what the
/// tracker hands back whenever it stops watching a finding (finalized,
/// retracted, or evicted), so the caller never has to re-look-up what kind
/// of finding it was after the tracker has already dropped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedFindingSummary {
    pub finding_id: CrossChainFindingId,
    pub bridge_or_pair: BridgeOrPair,
    pub kind: FindingKind,
}

#[derive(Debug, Clone)]
struct TrackedFinding {
    bridge_or_pair: BridgeOrPair,
    kind: FindingKind,
    /// The `(chain, block hash)` legs not yet past finality depth — the
    /// finding is fully final, and no longer tracked, once this is empty.
    pending_legs: HashSet<LegKey>,
    recorded_at: DateTime<Utc>,
}

impl TrackedFinding {
    fn summary(&self, finding_id: CrossChainFindingId) -> TrackedFindingSummary {
        TrackedFindingSummary {
            finding_id,
            bridge_or_pair: self.bridge_or_pair.clone(),
            kind: self.kind,
        }
    }
}

/// The pure core: which correlated findings are still waiting on which legs'
/// finality. See the module docs for the full design.
pub struct FindingFinalityTracker {
    retention: TimeDelta,
    capacity: usize,
    findings: HashMap<CrossChainFindingId, TrackedFinding>,
    /// Reverse index: a leg's `(chain, block hash)` -> every finding still
    /// waiting on it. Lets a `BlockReverted`/`BlockFinalized` for one block
    /// resolve directly to the (typically zero or one) affected findings
    /// instead of scanning every tracked finding.
    by_leg: HashMap<LegKey, HashSet<CrossChainFindingId>>,
    /// Age index: `(recorded_at, finding_id.0)` for every tracked finding,
    /// letting eviction find the globally-oldest finding in O(log n) instead
    /// of scanning `findings` on every write. Kept in exact lockstep with
    /// `findings` by [`Self::remove_finding`] (the one path every removal —
    /// finalize-to-empty, revert, or eviction itself — goes through), so
    /// there is never a stale/"ghost" entry to lazily skip past.
    by_age: BTreeSet<(DateTime<Utc>, Uuid)>,
}

impl FindingFinalityTracker {
    pub fn new(retention: TimeDelta, capacity: usize) -> Self {
        Self {
            retention,
            capacity,
            findings: HashMap::new(),
            by_leg: HashMap::new(),
            by_age: BTreeSet::new(),
        }
    }

    /// How many findings are currently tracked (awaiting finality) — the
    /// memory-DoS gauge the shell exports (§19).
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Remove one finding entirely — from `findings`, `by_age`, and every
    /// leg it was still pending on in `by_leg`. The single path every full
    /// removal (finalize-to-empty, revert, eviction) goes through, so the
    /// three indices can never drift apart.
    fn remove_finding(&mut self, id: CrossChainFindingId) -> Option<TrackedFinding> {
        let finding = self.findings.remove(&id)?;
        self.by_age.remove(&(finding.recorded_at, id.0));
        for leg in &finding.pending_legs {
            if let Some(ids) = self.by_leg.get_mut(leg) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.by_leg.remove(leg);
                }
            }
        }
        Some(finding)
    }

    /// Insert a finding's legs *without* running the eviction sweep — the
    /// changelog-replay counterpart to `CandidateLegBuffer::seed`: every
    /// historical fact is applied first, and eviction runs once against real
    /// "now" at the end of replay ([`Self::evict_now`]), mirroring
    /// `CorrelationActor::new_with_seed`'s seed-then-evict-once shape. Live
    /// callers want [`Self::record_finding`] instead, which sweeps on every
    /// call.
    pub fn insert_raw(
        &mut self,
        finding_id: CrossChainFindingId,
        bridge_or_pair: BridgeOrPair,
        kind: FindingKind,
        legs: Vec<LegKey>,
        recorded_at: DateTime<Utc>,
    ) {
        let pending_legs: HashSet<LegKey> = legs.into_iter().collect();
        for &leg in &pending_legs {
            self.by_leg.entry(leg).or_default().insert(finding_id);
        }
        self.by_age.insert((recorded_at, finding_id.0));
        self.findings.insert(
            finding_id,
            TrackedFinding {
                bridge_or_pair,
                kind,
                pending_legs,
                recorded_at,
            },
        );
    }

    /// Start tracking a newly-published finding's legs, then immediately
    /// sweep stale/over-capacity entries against `now` (see module docs'
    /// "bounded memory") — the tracker itself stays silent about what it
    /// evicted; the caller logs/alerts on the returned summaries, same split
    /// as [`crate::buffer::CandidateLegBuffer`].
    pub fn record_finding(
        &mut self,
        finding_id: CrossChainFindingId,
        bridge_or_pair: BridgeOrPair,
        kind: FindingKind,
        legs: Vec<LegKey>,
        now: DateTime<Utc>,
    ) -> Vec<TrackedFindingSummary> {
        self.insert_raw(finding_id, bridge_or_pair, kind, legs, now);
        self.sweep(now)
    }

    /// One leg reached finality depth (§15): clear it from every finding
    /// waiting on it, dropping (and returning) any finding whose *last*
    /// pending leg this was — it is now fully final and immune to a later
    /// reorg, so there is nothing left for this tracker to watch it for.
    pub fn on_block_finalized(&mut self, chain: Chain, hash: B256) -> Vec<TrackedFindingSummary> {
        let Some(ids) = self.by_leg.remove(&(chain, hash)) else {
            return Vec::new();
        };
        let mut fully_final = Vec::new();
        for id in ids {
            if let Some(finding) = self.findings.get_mut(&id) {
                finding.pending_legs.remove(&(chain, hash));
                if finding.pending_legs.is_empty() {
                    if let Some(finding) = self.remove_finding(id) {
                        fully_final.push(finding.summary(id));
                    }
                }
            }
        }
        fully_final
    }

    /// One leg's block was reverted (§15): retract every finding waiting on
    /// it outright — a finding is only as final as its least-final leg
    /// (§24), so it does not matter whether the finding's *other* legs are
    /// still fine; this one reverting is already enough. Retracted findings
    /// stop being tracked (their remaining legs, if any, are removed from
    /// the reverse index too).
    pub fn on_block_reverted(&mut self, chain: Chain, hash: B256) -> Vec<TrackedFindingSummary> {
        let Some(ids) = self.by_leg.remove(&(chain, hash)) else {
            return Vec::new();
        };
        let mut retracted = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(finding) = self.remove_finding(id) {
                retracted.push(finding.summary(id));
            }
        }
        retracted
    }

    /// Drop findings recorded longer than `retention` ago, then enforce the
    /// hard capacity backstop — both oldest-first via `by_age`, both O(log
    /// n) per eviction. See module docs' "bounded memory".
    fn sweep(&mut self, now: DateTime<Utc>) -> Vec<TrackedFindingSummary> {
        let mut evicted = Vec::new();
        while let Some(&(recorded_at, uuid)) = self.by_age.iter().next() {
            if now - recorded_at <= self.retention {
                break;
            }
            if let Some(finding) = self.remove_finding(CrossChainFindingId(uuid)) {
                evicted.push(finding.summary(CrossChainFindingId(uuid)));
            }
        }
        if self.capacity != 0 {
            while self.findings.len() > self.capacity {
                let Some(&(_, uuid)) = self.by_age.iter().next() else {
                    break;
                };
                if let Some(finding) = self.remove_finding(CrossChainFindingId(uuid)) {
                    evicted.push(finding.summary(CrossChainFindingId(uuid)));
                }
            }
        }
        evicted
    }

    /// Run [`Self::sweep`] against real "now" — the one-shot pass
    /// [`crate::finding_changelog::replay`] runs after every historical
    /// entry has been applied via [`Self::insert_raw`].
    pub fn evict_now(&mut self) -> Vec<TrackedFindingSummary> {
        self.sweep(Utc::now())
    }
}

/// Concurrent, **durable** [`FindingFinalityTracker`] shared between every
/// [`crate::actor::CorrelationActor`] (the writer, via
/// [`Self::record_finding`]) and the one [`FinalityConsumer`] task (also a
/// writer, via [`Self::on_block_reverted`]/[`Self::on_block_finalized`]) —
/// mirrors `simulation::reorg::SharedOrphanedBlocks`'s sharing role, plus
/// durability: every method here journals the call to
/// `crate::finding_changelog` *before* applying it to the in-memory core
/// (the same durable-before-applied ordering
/// [`crate::actor::CorrelationActor::run`] already gives the leg buffer), so
/// a crash never loses a call this process already committed to. A `Mutex`
/// guards the in-memory core; it is ample since every operation on it is a
/// bounded hash-map mutation, never held across an `.await` (the changelog
/// append, which does `.await`, always happens first, outside the lock).
pub struct SharedFindingFinalityTracker {
    tracker: Mutex<FindingFinalityTracker>,
    changelog: Arc<dyn FindingChangelogSink>,
    shutdown: CancellationToken,
    publish_backoff: Duration,
}

impl SharedFindingFinalityTracker {
    /// A fresh, empty tracker — the boot path when there is nothing to
    /// replay (or replay is being skipped, e.g. in tests). Live callers that
    /// warm-start from the changelog want [`Self::from_tracker`] instead.
    pub fn new(
        retention: TimeDelta,
        capacity: usize,
        changelog: Arc<dyn FindingChangelogSink>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Self::from_tracker(
            FindingFinalityTracker::new(retention, capacity),
            changelog,
            shutdown,
        )
    }

    /// Wrap an already-populated [`FindingFinalityTracker`] — the warm-start
    /// path `main.rs` uses after [`crate::finding_changelog::replay`].
    pub fn from_tracker(
        tracker: FindingFinalityTracker,
        changelog: Arc<dyn FindingChangelogSink>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            tracker: Mutex::new(tracker),
            changelog,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        })
    }

    fn with_tracker<T>(&self, f: impl FnOnce(&mut FindingFinalityTracker) -> T) -> T {
        let mut tracker = self
            .tracker
            .lock()
            .expect("finding-finality tracker lock poisoned");
        f(&mut tracker)
    }

    pub async fn record_finding(
        &self,
        finding_id: CrossChainFindingId,
        bridge_or_pair: BridgeOrPair,
        kind: FindingKind,
        legs: Vec<LegKey>,
        now: DateTime<Utc>,
    ) -> Vec<TrackedFindingSummary> {
        let entry = FindingChangelogEntry::Recorded {
            finding_id,
            bridge_or_pair: bridge_or_pair.clone(),
            kind,
            legs: legs.clone(),
            recorded_at: now,
        };
        self.changelog
            .append(&entry, self.publish_backoff, &self.shutdown)
            .await;
        self.with_tracker(|t| t.record_finding(finding_id, bridge_or_pair, kind, legs, now))
    }

    pub async fn on_block_finalized(&self, chain: Chain, hash: B256) -> Vec<TrackedFindingSummary> {
        let entry = FindingChangelogEntry::LegFinalized { chain, hash };
        self.changelog
            .append(&entry, self.publish_backoff, &self.shutdown)
            .await;
        self.with_tracker(|t| t.on_block_finalized(chain, hash))
    }

    pub async fn on_block_reverted(&self, chain: Chain, hash: B256) -> Vec<TrackedFindingSummary> {
        let entry = FindingChangelogEntry::LegReverted { chain, hash };
        self.changelog
            .append(&entry, self.publish_backoff, &self.shutdown)
            .await;
        self.with_tracker(|t| t.on_block_reverted(chain, hash))
    }

    pub fn len(&self) -> usize {
        self.with_tracker(|t| t.len())
    }

    pub fn is_empty(&self) -> bool {
        self.with_tracker(|t| t.is_empty())
    }
}

/// Audit reason stamped on a `CrossChainFindingRetracted`, naming the
/// reverted leg — mirrors `simulation::reorg::retraction_reason`'s
/// explainability, with the chain named too since (unlike that single-chain
/// consumer) one finding's legs can span several.
fn retraction_reason(chain: Chain, reverted: &BlockReverted) -> String {
    format!(
        "chain {} block {} ({:#x}) reverted by reorg, replaced by {:#x}",
        chain.id(),
        reverted.block.number,
        reverted.block.hash,
        reverted.replaced_by
    )
}

/// The two topics [`FinalityConsumer`] subscribes to.
const CONSUMED_EVENT_TYPES: &[&str] = &["BlockReverted", "BlockFinalized"];

pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build a **broadcast** consumer for [`FinalityConsumer`] — mirrors
/// `simulation::reorg::build_broadcast_consumer` exactly, and for the same
/// reason: every replica must see every chain's `BlockReverted`/
/// `BlockFinalized`, since [`FindingFinalityTracker`]'s state is sharded per
/// replica by which bridge/pair actors that replica owns (§17). `group_id`
/// must therefore be **unique per process**, not shared like an
/// offset-committing consumer group.
pub fn build_broadcast_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer> {
    ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("group.id", group_id)
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", "latest")
        .create()
        .map_err(anyhow::Error::from)
}

/// The finality/reorg effectful shell: drives [`FindingFinalityTracker`] off
/// `BlockReverted`/`BlockFinalized` and publishes
/// [`CrossChainFindingRetracted`] for whatever a revert retracted. See the
/// module docs for the full design.
pub struct FinalityConsumer {
    tracker: Arc<SharedFindingFinalityTracker>,
    sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    publish_backoff: Duration,
}

impl FinalityConsumer {
    pub fn new(
        tracker: Arc<SharedFindingFinalityTracker>,
        sink: Arc<dyn EventSink>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            tracker,
            sink,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        }
    }

    async fn process(&self, chain: Chain, payload: DomainEvent) -> Handled {
        match payload {
            DomainEvent::BlockReverted(reverted) => {
                let retracted = self
                    .tracker
                    .on_block_reverted(chain, reverted.block.hash)
                    .await;
                if !retracted.is_empty() {
                    let reason = retraction_reason(chain, &reverted);
                    for finding in retracted {
                        tracing::info!(
                            finding_id = %finding.finding_id,
                            bridge_or_pair = %finding.bridge_or_pair,
                            kind = finding.kind.as_str(),
                            chain = chain.id(),
                            block = reverted.block.number,
                            "retracting cross-chain finding: a leg's block was reverted"
                        );
                        crate::metrics::record_finding_retracted(
                            &finding.bridge_or_pair,
                            finding.kind.as_str(),
                        );
                        self.publish(
                            chain,
                            DomainEvent::CrossChainFindingRetracted(CrossChainFindingRetracted {
                                finding_id: finding.finding_id,
                                reason: reason.clone(),
                            }),
                        )
                        .await;
                    }
                }
                crate::metrics::record_pending_findings(self.tracker.len());
                if self.shutdown.is_cancelled() {
                    Handled::Stop
                } else {
                    Handled::Commit
                }
            }
            DomainEvent::BlockFinalized(finalized) => {
                self.on_finalized(chain, &finalized).await;
                crate::metrics::record_pending_findings(self.tracker.len());
                Handled::Commit
            }
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on the finality topics; skipping"
                );
                Handled::Commit
            }
        }
    }

    async fn on_finalized(&self, chain: Chain, finalized: &BlockFinalized) {
        let fully_final = self
            .tracker
            .on_block_finalized(chain, finalized.block.hash)
            .await;
        for finding in fully_final {
            tracing::debug!(
                finding_id = %finding.finding_id,
                bridge_or_pair = %finding.bridge_or_pair,
                kind = finding.kind.as_str(),
                "cross-chain finding fully finalized; no longer tracked for reorg"
            );
            crate::metrics::record_finding_finalized(
                &finding.bridge_or_pair,
                finding.kind.as_str(),
            );
        }
    }

    async fn publish(&self, chain: Chain, payload: DomainEvent) {
        publish_resilient(
            self.sink.as_ref(),
            EventEnvelope::new(chain, payload),
            self.publish_backoff,
            &self.shutdown,
        )
        .await;
    }

    /// Drive the consumer off Kafka until shutdown or a fatal subscribe
    /// error, via the shared [`run_consumer`] loop. No DLQ: this is a
    /// live-tail broadcast consumer (see [`build_broadcast_consumer`]) — a
    /// skip here parks nothing the backbone doesn't already durably own, the
    /// same reasoning `simulation::reorg::run_revert_tracker` gives.
    pub async fn run(self, consumer: StreamConsumer, retry_backoff: Duration) -> Result<()> {
        let topics = consumed_topics();
        let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
        let shutdown = self.shutdown.clone();
        run_consumer(
            consumer,
            &topic_refs,
            "cross-chain-correlator-finality",
            retry_backoff,
            None,
            self,
            &shutdown,
        )
        .await
    }
}

#[async_trait]
impl EventHandler for FinalityConsumer {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        self.process(envelope.chain, envelope.payload).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding_changelog::RecordingFindingChangelogWriter;
    use events::primitives::BlockRef;

    fn window() -> TimeDelta {
        TimeDelta::hours(1)
    }

    fn bridge() -> BridgeOrPair {
        BridgeOrPair("usdc-eth-base".to_owned())
    }

    fn leg(chain: Chain, tag: u8) -> LegKey {
        (chain, B256::repeat_byte(tag))
    }

    fn test_changelog() -> Arc<dyn FindingChangelogSink> {
        Arc::new(RecordingFindingChangelogWriter::default())
    }

    fn shared_tracker(retention: TimeDelta, capacity: usize) -> Arc<SharedFindingFinalityTracker> {
        SharedFindingFinalityTracker::new(
            retention,
            capacity,
            test_changelog(),
            CancellationToken::new(),
        )
    }

    // ── FindingFinalityTracker: the pure core ────────────────────────────

    #[test]
    fn a_finding_is_retracted_when_any_leg_reverts() {
        let mut t = FindingFinalityTracker::new(window(), 100);
        let id = CrossChainFindingId::new();
        let now = Utc::now();
        t.record_finding(
            id,
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::ETHEREUM, 1), leg(Chain::BASE, 2)],
            now,
        );

        let retracted = t.on_block_reverted(Chain::ETHEREUM, B256::repeat_byte(1));
        assert_eq!(retracted.len(), 1);
        assert_eq!(retracted[0].finding_id, id);
        assert_eq!(retracted[0].kind, FindingKind::BridgeMev);
        assert!(
            t.is_empty(),
            "the retracted finding must no longer be tracked"
        );
    }

    #[test]
    fn a_finding_is_not_final_until_every_leg_finalizes() {
        let mut t = FindingFinalityTracker::new(window(), 100);
        let id = CrossChainFindingId::new();
        let now = Utc::now();
        t.record_finding(
            id,
            bridge(),
            FindingKind::CrossChainMev,
            vec![leg(Chain::ETHEREUM, 1), leg(Chain::BASE, 2)],
            now,
        );

        let fully_final = t.on_block_finalized(Chain::ETHEREUM, B256::repeat_byte(1));
        assert!(
            fully_final.is_empty(),
            "one leg finalizing must not finalize a finding with a still-pending leg"
        );
        assert_eq!(t.len(), 1, "still tracked, waiting on the other leg");

        let fully_final = t.on_block_finalized(Chain::BASE, B256::repeat_byte(2));
        assert_eq!(fully_final.len(), 1);
        assert_eq!(fully_final[0].finding_id, id);
        assert!(
            t.is_empty(),
            "fully finalized findings are no longer tracked"
        );
    }

    #[test]
    fn a_fully_finalized_finding_can_no_longer_be_retracted() {
        // Once every leg is finalized (§15), the finding is immune to a
        // later revert of one of those same blocks — it's already dropped
        // from the tracker, so a revert now finds nothing to retract.
        let mut t = FindingFinalityTracker::new(window(), 100);
        let id = CrossChainFindingId::new();
        let now = Utc::now();
        t.record_finding(
            id,
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::ETHEREUM, 1)],
            now,
        );
        t.on_block_finalized(Chain::ETHEREUM, B256::repeat_byte(1));

        let retracted = t.on_block_reverted(Chain::ETHEREUM, B256::repeat_byte(1));
        assert!(retracted.is_empty());
    }

    #[test]
    fn reverting_an_untracked_block_is_a_noop() {
        let mut t = FindingFinalityTracker::new(window(), 100);
        assert!(t
            .on_block_reverted(Chain::ETHEREUM, B256::repeat_byte(9))
            .is_empty());
    }

    #[test]
    fn a_shared_leg_hash_on_a_different_chain_does_not_match() {
        // Legs are keyed by (chain, hash) together — the same hash byte
        // pattern on a different chain id must not accidentally collide.
        let mut t = FindingFinalityTracker::new(window(), 100);
        let id = CrossChainFindingId::new();
        t.record_finding(
            id,
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::ETHEREUM, 1)],
            Utc::now(),
        );

        assert!(t
            .on_block_reverted(Chain::BASE, B256::repeat_byte(1))
            .is_empty());
        assert_eq!(t.len(), 1, "the actual (chain, hash) leg is untouched");
    }

    #[test]
    fn two_findings_sharing_a_leg_both_retract_on_one_revert() {
        let mut t = FindingFinalityTracker::new(window(), 100);
        let a = CrossChainFindingId::new();
        let b = CrossChainFindingId::new();
        let now = Utc::now();
        t.record_finding(
            a,
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::ETHEREUM, 1)],
            now,
        );
        t.record_finding(
            b,
            bridge(),
            FindingKind::CrossChainMev,
            vec![leg(Chain::ETHEREUM, 1)],
            now,
        );

        let retracted = t.on_block_reverted(Chain::ETHEREUM, B256::repeat_byte(1));
        assert_eq!(retracted.len(), 2);
        assert!(t.is_empty());
    }

    #[test]
    fn stale_findings_are_evicted_past_the_retention_window() {
        let mut t = FindingFinalityTracker::new(TimeDelta::minutes(10), 100);
        let id = CrossChainFindingId::new();
        let old = Utc::now() - TimeDelta::hours(1);
        t.record_finding(
            id,
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::ETHEREUM, 1)],
            old,
        );

        // The next record_finding call sweeps stale entries against `now`.
        let other = CrossChainFindingId::new();
        let evicted = t.record_finding(
            other,
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::BASE, 2)],
            Utc::now(),
        );
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].finding_id, id);
        assert_eq!(t.len(), 1, "only the fresh finding remains");

        // The stale finding's leg is no longer tracked either.
        assert!(t
            .on_block_reverted(Chain::ETHEREUM, B256::repeat_byte(1))
            .is_empty());
    }

    #[test]
    fn the_oldest_findings_are_evicted_over_capacity() {
        let mut t = FindingFinalityTracker::new(window(), 1);
        let first = CrossChainFindingId::new();
        let now = Utc::now();
        t.record_finding(
            first,
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::ETHEREUM, 1)],
            now,
        );

        let second = CrossChainFindingId::new();
        let evicted = t.record_finding(
            second,
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::BASE, 2)],
            now + TimeDelta::seconds(1),
        );
        assert_eq!(evicted.len(), 1);
        assert_eq!(
            evicted[0].finding_id, first,
            "the older finding is evicted first"
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn insert_raw_never_evicts_on_its_own() {
        let mut t = FindingFinalityTracker::new(TimeDelta::minutes(10), 100);
        let old = Utc::now() - TimeDelta::hours(2);
        t.insert_raw(
            CrossChainFindingId::new(),
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::ETHEREUM, 1)],
            old,
        );
        assert_eq!(t.len(), 1, "insert_raw applies the fact without sweeping");
        let evicted = t.evict_now();
        assert_eq!(
            evicted.len(),
            1,
            "evict_now then prunes it against real now"
        );
    }

    // ── SharedFindingFinalityTracker: the durable concurrent wrapper ─────

    #[tokio::test]
    async fn shared_tracker_reads_and_writes_through() {
        let shared = shared_tracker(window(), 100);
        let id = CrossChainFindingId::new();
        shared
            .record_finding(
                id,
                bridge(),
                FindingKind::BridgeMev,
                vec![leg(Chain::ETHEREUM, 1)],
                Utc::now(),
            )
            .await;
        assert_eq!(shared.len(), 1);

        let retracted = shared
            .on_block_reverted(Chain::ETHEREUM, B256::repeat_byte(1))
            .await;
        assert_eq!(retracted.len(), 1);
        assert!(shared.is_empty());
    }

    #[tokio::test]
    async fn shared_tracker_journals_every_call_before_applying_it() {
        let changelog = Arc::new(RecordingFindingChangelogWriter::default());
        let changelog_dyn: Arc<dyn FindingChangelogSink> = changelog.clone();
        let shared = SharedFindingFinalityTracker::new(
            window(),
            100,
            changelog_dyn,
            CancellationToken::new(),
        );
        let id = CrossChainFindingId::new();
        shared
            .record_finding(
                id,
                bridge(),
                FindingKind::BridgeMev,
                vec![leg(Chain::ETHEREUM, 1)],
                Utc::now(),
            )
            .await;
        shared
            .on_block_reverted(Chain::ETHEREUM, B256::repeat_byte(1))
            .await;

        let entries = changelog.entries();
        assert_eq!(entries.len(), 2);
        assert!(matches!(entries[0], FindingChangelogEntry::Recorded { .. }));
        assert!(matches!(
            entries[1],
            FindingChangelogEntry::LegReverted { .. }
        ));
    }

    #[tokio::test]
    async fn from_tracker_wraps_an_already_populated_core() {
        let mut core = FindingFinalityTracker::new(window(), 100);
        let id = CrossChainFindingId::new();
        core.insert_raw(
            id,
            bridge(),
            FindingKind::BridgeMev,
            vec![leg(Chain::ETHEREUM, 1)],
            Utc::now(),
        );

        let shared = SharedFindingFinalityTracker::from_tracker(
            core,
            test_changelog(),
            CancellationToken::new(),
        );
        assert_eq!(
            shared.len(),
            1,
            "the warm-started state is visible immediately"
        );
    }

    // ── FinalityConsumer: the effectful shell ─────────────────────────────

    fn reverted(number: u64, hash: u8) -> BlockReverted {
        BlockReverted {
            block: BlockRef::new(number, B256::repeat_byte(hash)),
            replaced_by: B256::repeat_byte(hash.wrapping_add(1)),
        }
    }

    fn finalized(number: u64, hash: u8) -> BlockFinalized {
        BlockFinalized {
            block: BlockRef::new(number, B256::repeat_byte(hash)),
        }
    }

    fn consumer(
        tracker: Arc<SharedFindingFinalityTracker>,
    ) -> (FinalityConsumer, Arc<event_bus::test_util::RecordingSink>) {
        let sink = Arc::new(event_bus::test_util::RecordingSink::default());
        let sink_dyn: Arc<dyn EventSink> = sink.clone();
        let mut c = FinalityConsumer::new(tracker, sink_dyn, CancellationToken::new());
        c.publish_backoff = Duration::from_millis(1);
        (c, sink)
    }

    #[tokio::test]
    async fn handle_publishes_a_retraction_for_a_reverted_leg() {
        let tracker = shared_tracker(window(), 100);
        let id = CrossChainFindingId::new();
        tracker
            .record_finding(
                id,
                bridge(),
                FindingKind::BridgeMev,
                vec![leg(Chain::ETHEREUM, 1)],
                Utc::now(),
            )
            .await;
        let (c, sink) = consumer(tracker.clone());

        let handled = c
            .handle(EventEnvelope::new(
                Chain::ETHEREUM,
                DomainEvent::BlockReverted(reverted(10, 1)),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);

        let published = sink.events();
        assert_eq!(published.len(), 1);
        match &published[0] {
            DomainEvent::CrossChainFindingRetracted(r) => assert_eq!(r.finding_id, id),
            other => panic!("expected CrossChainFindingRetracted, got {other:?}"),
        }
        assert!(tracker.is_empty());
    }

    #[tokio::test]
    async fn handle_publishes_nothing_for_a_revert_with_no_tracked_finding() {
        let tracker = shared_tracker(window(), 100);
        let (c, sink) = consumer(tracker);

        let handled = c
            .handle(EventEnvelope::new(
                Chain::ETHEREUM,
                DomainEvent::BlockReverted(reverted(10, 1)),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(sink.events().is_empty());
    }

    #[tokio::test]
    async fn handle_finalizes_without_publishing() {
        let tracker = shared_tracker(window(), 100);
        let id = CrossChainFindingId::new();
        tracker
            .record_finding(
                id,
                bridge(),
                FindingKind::BridgeMev,
                vec![leg(Chain::ETHEREUM, 1)],
                Utc::now(),
            )
            .await;
        let (c, sink) = consumer(tracker.clone());

        let handled = c
            .handle(EventEnvelope::new(
                Chain::ETHEREUM,
                DomainEvent::BlockFinalized(finalized(10, 1)),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(sink.events().is_empty(), "finalizing publishes nothing");
        assert!(tracker.is_empty(), "the fully-finalized finding is dropped");
    }

    #[tokio::test]
    async fn handle_ignores_an_unrelated_event_type() {
        let tracker = shared_tracker(window(), 100);
        let (c, sink) = consumer(tracker);
        let handled = c
            .handle(EventEnvelope::new(
                Chain::ETHEREUM,
                DomainEvent::BlockCanonicalized(events::chain::BlockCanonicalized {
                    block: BlockRef::new(1, B256::ZERO),
                }),
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(sink.events().is_empty());
    }

    #[test]
    fn consumed_topics_covers_both_reverted_and_finalized() {
        assert_eq!(
            consumed_topics(),
            vec![
                "mev.events.BlockReverted".to_owned(),
                "mev.events.BlockFinalized".to_owned(),
            ]
        );
    }
}
