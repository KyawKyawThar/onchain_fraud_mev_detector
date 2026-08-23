//! The block-production consumer (§10, Sprint 11 t1) — the effectful shell
//! around the pure [`ProductionBook`] fold: five topics in, ClickHouse
//! snapshots (and the occasional heuristic `BuilderAddress` label) out.
//!
//! ## Topics and what each one contributes
//!
//! * **`BlockCanonicalized`** — the trigger: fetch the block's header + body
//!   from the chain ([`BlockFactsSource`]), ask the configured MEV-Boost
//!   relays who delivered it ([`RelaySource`]), resolve the builder's name
//!   from the intelligence label store (§10 — labels, never a hardcoded
//!   table), and open the record.
//! * **`DetectorTriggered`** — teaches the book `tx → block`, the join key
//!   `IncidentCreated` deliberately lacks (locked schema, §2).
//! * **`IncidentCreated`** — folds a confirmed incident's kind + profit into
//!   its block's record.
//! * **`IncidentRetracted`** — subtracts exactly what that incident added (§15).
//! * **`BlockReverted`** — marks the record's final snapshot reverted (§15).
//! * **`BridgeMevDetected`/`CrossChainMevDetected`** (§24, Sprint 17 t4) — a
//!   cross-chain finding's legs each carry their own `chain` (unlike every
//!   event above, whose *envelope* is tagged to this pipeline's one chain),
//!   so this consumer folds in only the legs whose `chain` matches
//!   [`ProductionConsumer::chain`], apportioning the finding's `profit` to
//!   whichever of *this chain's* blocks the finding actually touched. Kept
//!   in `cross_chain_bridge_count`/`cross_chain_arb_count`/
//!   `cross_chain_provisional_usd` — separate counters from the confirmed-
//!   incident ones, since a cross-chain finding is never simulation-confirmed
//!   (§24: `provisional` stays `true` forever) and conflating the two would
//!   misreport a builder's *confirmed* MEV total.
//! * **`CrossChainFindingRetracted`** — subtracts exactly what that finding
//!   added on this chain (§15/§24: a finding is only as final as its
//!   least-final leg, so any leg's reorg retracts the whole thing).
//!
//! ## Builder auto-labeling (§8.1)
//!
//! When a relay proves the fee recipient won a MEV-Boost auction and the
//! address carries no active `BuilderAddress` label, this consumer mints one
//! heuristically — value from the block's own graffiti (or the builder
//! pubkey), `Heuristic` provenance band, deterministic [`seeded_label_id`] so
//! a redelivery no-ops — publishing `LabelAdded` and evicting the hot cache,
//! exactly like the attribution flywheel. The §10 record then reads the label
//! back on the *next* block that fee recipient builds; the current record
//! carries the same value directly.
//!
//! ## At-least-once without lost snapshots
//!
//! The fold mutates in-memory state; the store append is the effect. A fold
//! that succeeded whose append then failed must not lose its snapshots to the
//! redelivery (which the book correctly treats as a duplicate). So snapshots
//! go through a **pending-writes queue**: fold first (queue the snapshots),
//! then flush the whole queue to ClickHouse — a flush failure leaves the queue
//! intact and returns `Retry`, and the redelivered event's no-op fold still
//! flushes what the failed pass queued. The queue only ever holds unflushed
//! work for the in-flight record, so it stays small by construction.
//!
//! On restart the book starts empty (offsets committed): incidents for blocks
//! whose records opened before the restart buffer until eviction — the same
//! documented seam as `simulation-projection`'s orphan buffer and the
//! attribution address book.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{
    handled, publish_resilient, run_consumer, EventHandler, EventSink, Handled, Transience,
};
use events::cross_chain::{
    BridgeMevDetected, CrossChainFindingKind, CrossChainFindingRetracted, CrossChainMevDetected,
};
use events::intelligence::LabelAdded;
use events::primitives::{AccountAddress, BlockRef, Chain, CrossChainFindingId};
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;

use crate::cache::{CacheError, HotCache};
use crate::model::{LabelKind, LabelRecord, LabelSource};
use crate::production::{
    heuristic_builder_value, sanitize_extra_data, BlockProductionRecord, BookCapacity,
    Contribution, CrossChainContribution, Folded, OpenFacts, ProductionBook, RelayAttribution,
};
use crate::production_source::{coinbase_transfers, BlockFactsSource, RelaySource, SourceFault};
use crate::production_store::{BlockProductionStore, ProductionStoreError};
use crate::seed::seeded_label_id;
use crate::store::{LabelStore, StoreError};

/// The event types this consumer subscribes to (see the module docs). An
/// explicit, closed list (not a `mev.events.*` regex) so a renamed/missing
/// topic fails loudly — the same discipline as every consumer on the backbone.
/// The three cross-chain finding types (§24, Sprint 17 t4) are **not**
/// chain-scoped by envelope the way the first five are (see
/// [`EventHandler::handle`]'s routing) — see the module docs.
const CONSUMED_EVENT_TYPES: &[&str] = &[
    "BlockCanonicalized",
    "BlockReverted",
    "DetectorTriggered",
    "IncidentCreated",
    "IncidentRetracted",
    "BridgeMevDetected",
    "CrossChainMevDetected",
    "CrossChainFindingRetracted",
];

/// The `source_detail` every relay-derived builder label carries — distinct
/// from every feed's and from the association flywheel's, so the
/// deterministic [`seeded_label_id`] can never collide across producers.
const PRODUCTION_SOURCE_DETAIL: &str = "mev_boost_relay_v1";

/// Snapshot rows appended (§19).
pub const PRODUCTION_SNAPSHOTS_TOTAL: &str = "intel_block_production_snapshots_total";
/// Records opened with a relay attribution vs. without one.
pub const PRODUCTION_RELAY_ATTRIBUTED_TOTAL: &str = "intel_block_production_relay_attributed_total";
pub const PRODUCTION_RELAY_MISSED_TOTAL: &str = "intel_block_production_relay_missed_total";
/// Heuristic `BuilderAddress` labels minted from relay evidence (§8.1).
pub const PRODUCTION_BUILDER_LABELS_MINTED_TOTAL: &str =
    "intel_block_production_builder_labels_minted_total";
/// Incidents buffered awaiting their trigger/record (an operational signal —
/// a persistently climbing value means a stalled upstream partition).
pub const PRODUCTION_INCIDENTS_BUFFERED_TOTAL: &str =
    "intel_block_production_incidents_buffered_total";
/// Cross-chain finding legs buffered awaiting their block's record (§24,
/// Sprint 17 t4) — tracked separately from
/// [`PRODUCTION_INCIDENTS_BUFFERED_TOTAL`] so a stalled cross-chain topic is
/// distinguishable from a stalled incident-correlation one.
pub const PRODUCTION_CROSS_CHAIN_BUFFERED_TOTAL: &str =
    "intel_block_production_cross_chain_buffered_total";

/// The topics the consumer subscribes to (one per [`CONSUMED_EVENT_TYPES`] entry).
pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build the consumer. Manual offset commit (`enable.auto.commit=false`) ties
/// the commit to a fully-flushed fold; `earliest` means a fresh group builds
/// records from the start of retained history (cf. the attribution consumer).
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "block-production")
}

/// A failure handling one event. Wraps every seam's error and forwards the
/// shared retry/skip decision (§4) — every fold and write here is idempotent,
/// so a transient retry converges.
#[derive(Debug, thiserror::Error)]
pub enum ProductionError {
    #[error(transparent)]
    Labels(#[from] StoreError),
    #[error(transparent)]
    Cache(#[from] CacheError),
    #[error(transparent)]
    Facts(#[from] SourceFault),
    #[error(transparent)]
    Append(#[from] ProductionStoreError),
    /// The node answered but doesn't know a *canonical* block yet — it is
    /// lagging the ingestion service's view; retrying will see it.
    #[error("canonical block {0} not yet known to the RPC node")]
    BlockNotYetKnown(String),
}

impl Transience for ProductionError {
    /// Whether retrying the same event could plausibly succeed.
    fn is_transient(&self) -> bool {
        match self {
            ProductionError::Labels(err) => err.is_transient(),
            ProductionError::Cache(err) => err.is_transient(),
            ProductionError::Facts(SourceFault::Rpc(_)) => true,
            ProductionError::Append(err) => err.is_transient(),
            ProductionError::BlockNotYetKnown(_) => true,
        }
    }
}

/// The in-memory state behind one lock: the pure book plus the pending-writes
/// queue (see the module docs on why snapshots queue before they flush).
struct BookState {
    book: ProductionBook,
    pending_writes: Vec<BlockProductionRecord>,
}

/// The block-production consumer: the fold, its sources, the label seam it
/// reads/mints through, the snapshot store, and the event sink for
/// `LabelAdded`.
pub struct ProductionConsumer {
    /// The one chain this pipeline attributes (§10 is PBS/Ethereum-specific and
    /// `facts` reads exactly one chain); other chains' events on the shared
    /// topics are commit-skipped in [`EventHandler::handle`] (Sprint 13 t2).
    chain: Chain,
    state: Mutex<BookState>,
    facts: Arc<dyn BlockFactsSource>,
    relays: Arc<dyn RelaySource>,
    labels: Arc<dyn LabelStore>,
    cache: Arc<dyn HotCache>,
    store: Arc<dyn BlockProductionStore>,
    sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    publish_backoff: Duration,
}

impl ProductionConsumer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: Chain,
        facts: Arc<dyn BlockFactsSource>,
        relays: Arc<dyn RelaySource>,
        labels: Arc<dyn LabelStore>,
        cache: Arc<dyn HotCache>,
        store: Arc<dyn BlockProductionStore>,
        sink: Arc<dyn EventSink>,
        shutdown: CancellationToken,
        capacity: BookCapacity,
    ) -> Self {
        Self {
            chain,
            state: Mutex::new(BookState {
                book: ProductionBook::new(capacity),
                pending_writes: Vec::new(),
            }),
            facts,
            relays,
            labels,
            cache,
            store,
            sink,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        }
    }

    /// Drive the consumer off Kafka until shutdown or a fatal subscribe error,
    /// via the shared [`run_consumer`] loop.
    pub async fn run(
        self,
        consumer: StreamConsumer<LagReporting>,
        retry_backoff: Duration,
        dlq: Option<&DeadLetterQueue>,
        shutdown: &CancellationToken,
    ) -> Result<()> {
        let topics = consumed_topics();
        let topic_refs: Vec<&str> = topics.iter().map(String::as_str).collect();
        run_consumer(
            consumer,
            &topic_refs,
            "block-production",
            retry_backoff,
            dlq,
            self,
            shutdown,
        )
        .await
    }

    /// Queue a fold's snapshots, then flush everything queued to the store.
    /// A flush failure leaves the queue intact (the fold's work survives the
    /// retry — see the module docs) and surfaces as the error.
    async fn queue_and_flush(
        &self,
        snapshots: Vec<BlockProductionRecord>,
    ) -> Result<(), ProductionError> {
        let to_write = {
            let mut state = self.state.lock().expect("production state mutex poisoned");
            state.pending_writes.extend(snapshots);
            state.pending_writes.clone()
        };
        if to_write.is_empty() {
            return Ok(());
        }
        self.store.append(&to_write).await?;
        metrics::counter!(PRODUCTION_SNAPSHOTS_TOTAL).increment(to_write.len() as u64);
        let mut state = self.state.lock().expect("production state mutex poisoned");
        // Only drop what this flush actually wrote — a concurrent queue (none
        // today: run_consumer is sequential) would keep its tail.
        state.pending_writes.drain(..to_write.len());
        Ok(())
    }

    /// Handle `BlockCanonicalized`: assemble and open the block's record (the
    /// one effectful gather — chain, relays, labels), then fold + flush.
    async fn open_block(
        &self,
        chain: Chain,
        block: BlockRef,
        at: DateTime<Utc>,
    ) -> Result<(), ProductionError> {
        let already_open = {
            let state = self.state.lock().expect("production state mutex poisoned");
            state.book.is_open(&block.hash)
        };
        if already_open {
            // Redelivery: the fold is a no-op, but a snapshot from the first
            // pass may still be queued (its flush failed) — flush it now.
            return self.queue_and_flush(Vec::new()).await;
        }

        let facts = self
            .facts
            .block_facts(block)
            .await?
            .ok_or_else(|| ProductionError::BlockNotYetKnown(format!("{:#x}", block.hash)))?;

        let relay = self.relays.attribution_for(block).await;
        match relay {
            Some(ref attribution) => {
                metrics::counter!(PRODUCTION_RELAY_ATTRIBUTED_TOTAL).increment(1);
                tracing::debug!(
                    block = block.number,
                    relay = %attribution.relay,
                    "relay attributed the block"
                );
            }
            None => {
                metrics::counter!(PRODUCTION_RELAY_MISSED_TOTAL).increment(1);
            }
        }

        let extra_data = sanitize_extra_data(&facts.extra_data);
        let builder_label = self
            .resolve_builder_label(facts.fee_recipient, &relay, &extra_data, chain, at)
            .await?;

        let record = BlockProductionRecord::open(
            chain,
            block,
            OpenFacts {
                fee_recipient: facts.fee_recipient,
                extra_data,
                relay,
                builder_label,
                coinbase_transfers: coinbase_transfers(&facts),
            },
            at,
        );

        let folded = {
            let mut state = self.state.lock().expect("production state mutex poisoned");
            state.book.open_record(record)
        };
        self.queue_and_flush(folded.into_snapshots()).await
    }

    /// The builder's display name for `fee_recipient` (§10): the strongest
    /// active `BuilderAddress` label — minting a heuristic one first when the
    /// address is unlabeled but a relay proved it won a MEV-Boost auction
    /// (§8.1 auto-labeling; see the module docs).
    async fn resolve_builder_label(
        &self,
        fee_recipient: AccountAddress,
        relay: &Option<RelayAttribution>,
        extra_data: &str,
        chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<Option<String>, ProductionError> {
        let labels = self.labels.labels_for(&fee_recipient, at).await?;
        let strongest = labels
            .into_iter()
            .filter(|label| label.kind == LabelKind::BuilderAddress)
            .max_by(|a, b| {
                a.confidence
                    .get()
                    .total_cmp(&b.confidence.get())
                    .then(a.created_at.cmp(&b.created_at))
            });
        if let Some(label) = strongest {
            return Ok(Some(label.value));
        }

        // Unlabeled: only relay-delivered blocks justify minting — a bare
        // feeRecipient with no bid trace could be an ordinary local validator.
        let Some(relay) = relay else {
            return Ok(None);
        };

        let value = heuristic_builder_value(extra_data, &relay.builder_pubkey);
        let mut minted = LabelRecord::new(
            fee_recipient,
            LabelKind::BuilderAddress,
            value.clone(),
            LabelSource::Heuristic,
            PRODUCTION_SOURCE_DETAIL,
            at,
        );
        // Deterministic id: a redelivered canonicalization re-derives the same
        // claim and `add_label` no-ops (the seeded-label discipline, §8.1).
        minted.label_id = seeded_label_id(
            PRODUCTION_SOURCE_DETAIL,
            &fee_recipient,
            LabelKind::BuilderAddress,
            &value,
        );

        if self.labels.add_label(&minted).await? {
            self.cache.evict(&fee_recipient).await?;
            metrics::counter!(PRODUCTION_BUILDER_LABELS_MINTED_TOTAL).increment(1);
            self.publish(
                chain,
                DomainEvent::LabelAdded(LabelAdded {
                    address: minted.address,
                    kind: <&str>::from(minted.kind).to_owned(),
                    value: minted.value.clone(),
                    confidence: minted.confidence,
                    source: <&str>::from(minted.source).to_owned(),
                }),
            )
            .await;
        }
        Ok(Some(value))
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

    /// Run one pure fold under the state lock, then flush its snapshots.
    async fn fold_and_flush(
        &self,
        fold: impl FnOnce(&mut ProductionBook) -> Folded,
    ) -> Result<(), ProductionError> {
        let folded = {
            let mut state = self.state.lock().expect("production state mutex poisoned");
            fold(&mut state.book)
        };
        if matches!(folded, Folded::Buffered) {
            // Only incident folds buffer (§19) — a persistently climbing rate
            // means a stalled upstream trigger/canonicalization partition.
            metrics::counter!(PRODUCTION_INCIDENTS_BUFFERED_TOTAL).increment(1);
        }
        self.queue_and_flush(folded.into_snapshots()).await
    }

    /// Run one pure cross-chain-finding fold under the state lock, then flush
    /// its snapshots — the cross-chain analogue of
    /// [`fold_and_flush`](Self::fold_and_flush), with its own buffered-count
    /// metric (§19, §24).
    async fn fold_cross_chain_and_flush(
        &self,
        fold: impl FnOnce(&mut ProductionBook) -> Folded,
    ) -> Result<(), ProductionError> {
        let folded = {
            let mut state = self.state.lock().expect("production state mutex poisoned");
            fold(&mut state.book)
        };
        if matches!(folded, Folded::Buffered) {
            metrics::counter!(PRODUCTION_CROSS_CHAIN_BUFFERED_TOTAL).increment(1);
        }
        self.queue_and_flush(folded.into_snapshots()).await
    }

    /// Fold every leg of a `BridgeMevDetected`/`CrossChainMevDetected` that
    /// lands on this book's own chain (§24, Sprint 17 t4) — a bridge finding
    /// has at most one such leg by construction (its two legs are on
    /// different chains, §24 task 2's join requirement); a cross-chain-cycle
    /// finding could in principle have more than one.
    async fn fold_finding_legs(
        &self,
        finding_id: CrossChainFindingId,
        legs: &[(Chain, BlockRef)],
        kind: CrossChainFindingKind,
        profit_usd: f64,
        at: DateTime<Utc>,
    ) -> Handled {
        for &(leg_chain, block) in legs {
            if leg_chain != self.chain {
                continue;
            }
            let contribution = CrossChainContribution { kind, profit_usd };
            let result = self
                .fold_cross_chain_and_flush(|book| {
                    book.fold_cross_chain_finding(finding_id, block, contribution, at)
                })
                .await;
            if let Err(err) = result {
                return handled(err, "block-production");
            }
        }
        Handled::Commit
    }

    async fn handle_bridge_finding(
        &self,
        finding: &BridgeMevDetected,
        at: DateTime<Utc>,
    ) -> Handled {
        let legs = [
            (finding.deposit_leg.chain, finding.deposit_leg.block),
            (finding.fill_leg.chain, finding.fill_leg.block),
        ];
        self.fold_finding_legs(
            finding.finding_id,
            &legs,
            CrossChainFindingKind::BridgeMev,
            finding.profit,
            at,
        )
        .await
    }

    async fn handle_cross_chain_mev(
        &self,
        finding: &CrossChainMevDetected,
        at: DateTime<Utc>,
    ) -> Handled {
        let legs: Vec<(Chain, BlockRef)> = finding
            .legs
            .iter()
            .map(|leg| (leg.chain, leg.block))
            .collect();
        self.fold_finding_legs(
            finding.finding_id,
            &legs,
            CrossChainFindingKind::CrossChainMev,
            finding.profit,
            at,
        )
        .await
    }

    async fn handle_cross_chain_retraction(
        &self,
        retracted: &CrossChainFindingRetracted,
        at: DateTime<Utc>,
    ) -> Handled {
        let result = self
            .fold_cross_chain_and_flush(|book| {
                book.retract_cross_chain_finding(retracted.finding_id, at)
            })
            .await;
        match result {
            Ok(()) => Handled::Commit,
            Err(err) => handled(err, "block-production"),
        }
    }
}

#[async_trait]
impl EventHandler for ProductionConsumer {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let at = envelope.occurred_at;
        let chain = envelope.chain;

        // Cross-chain finding events (§24) are routed before the single-chain
        // early-exit below: unlike every other topic this consumer reads,
        // their *envelope* chain (§17's fill-leg/last-leg convention) need
        // not be this pipeline's chain even when one of the finding's *legs*
        // is — each handler filters legs itself (see the module docs).
        match &envelope.payload {
            DomainEvent::BridgeMevDetected(finding) => {
                return self.handle_bridge_finding(finding, at).await;
            }
            DomainEvent::CrossChainMevDetected(finding) => {
                return self.handle_cross_chain_mev(finding, at).await;
            }
            DomainEvent::CrossChainFindingRetracted(retracted) => {
                return self.handle_cross_chain_retraction(retracted, at).await;
            }
            _ => {}
        }

        // Another chain's event on the shared topics (Sprint 13 t2): this
        // pipeline attributes exactly one chain (its facts RPC and relays are
        // that chain's), so commit-skip rather than error on a block hash the
        // RPC will never know.
        if chain != self.chain {
            return Handled::Commit;
        }
        let result = match envelope.payload {
            DomainEvent::BlockCanonicalized(canonicalized) => {
                self.open_block(chain, canonicalized.block, at).await
            }
            DomainEvent::DetectorTriggered(trigger) => {
                self.fold_and_flush(|book| book.observe_trigger(trigger.block, &trigger.txs))
                    .await
            }
            DomainEvent::IncidentCreated(incident) => {
                let contribution = Contribution {
                    kind: incident.kind,
                    profit_usd: incident.profit,
                };
                self.fold_and_flush(|book| {
                    book.fold_incident(incident.incident_id, contribution, &incident.txs, at)
                })
                .await
            }
            DomainEvent::IncidentRetracted(retracted) => {
                self.fold_and_flush(|book| book.retract_incident(retracted.incident_id, at))
                    .await
            }
            DomainEvent::BlockReverted(reverted) => {
                self.fold_and_flush(|book| book.revert_block(reverted.block.hash, at))
                    .await
            }
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on block-production topics; skipping"
                );
                return Handled::Commit;
            }
        };

        match result {
            Ok(()) => Handled::Commit,
            Err(err) => handled(err, "block-production"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};
    use event_bus::test_util::RecordingSink;
    use events::chain::{BlockCanonicalized, BlockReverted};
    use events::detection::DetectorTriggered;
    use events::primitives::{AlertKind, Confidence, DetectorRef, IncidentId, Severity};
    use events::simulation::{IncidentCreated, IncidentRetracted};
    use uuid::Uuid;

    use crate::production_source::{BlockFacts, TxSummary};
    use crate::test_util::{
        FixedBlockFacts, FixedRelaySource, InMemoryHotCache, InMemoryIntelligenceStore,
        RecordingProductionStore,
    };

    struct Harness {
        consumer: ProductionConsumer,
        facts: Arc<FixedBlockFacts>,
        relays: Arc<FixedRelaySource>,
        labels: Arc<InMemoryIntelligenceStore>,
        store: Arc<RecordingProductionStore>,
        sink: Arc<RecordingSink>,
    }

    fn harness() -> Harness {
        let facts = Arc::new(FixedBlockFacts::new());
        let relays = Arc::new(FixedRelaySource::new());
        let labels = Arc::new(InMemoryIntelligenceStore::new());
        let store = Arc::new(RecordingProductionStore::new());
        let sink = Arc::new(RecordingSink::default());
        let consumer = ProductionConsumer::new(
            Chain::ETHEREUM,
            facts.clone(),
            relays.clone(),
            labels.clone(),
            Arc::new(InMemoryHotCache::new()),
            store.clone(),
            sink.clone(),
            CancellationToken::new(),
            BookCapacity::default(),
        );
        Harness {
            consumer,
            facts,
            relays,
            labels,
            store,
            sink,
        }
    }

    fn hash(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn block(n: u64, byte: u8) -> BlockRef {
        BlockRef::new(n, hash(byte))
    }

    fn coinbase() -> AccountAddress {
        AccountAddress::repeat_byte(0xfe)
    }

    fn facts_with_tip() -> BlockFacts {
        BlockFacts {
            fee_recipient: coinbase(),
            extra_data: b"beaverbuild.org".to_vec(),
            txs: vec![TxSummary {
                hash: hash(0x11),
                from: AccountAddress::repeat_byte(0x01),
                to: Some(coinbase()),
                value_wei: U256::from(1_000u64),
            }],
        }
    }

    fn attribution() -> RelayAttribution {
        RelayAttribution {
            relay: "flashbots".to_owned(),
            builder_pubkey: "0x96a5".to_owned(),
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    fn envelope(payload: DomainEvent, secs: i64) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), at(secs), Chain::ETHEREUM, payload)
    }

    fn canonicalized(b: BlockRef, secs: i64) -> EventEnvelope {
        envelope(
            DomainEvent::BlockCanonicalized(BlockCanonicalized { block: b }),
            secs,
        )
    }

    fn triggered(b: BlockRef, txs: Vec<B256>, secs: i64) -> EventEnvelope {
        envelope(
            DomainEvent::DetectorTriggered(DetectorTriggered {
                detector: DetectorRef {
                    id: "sandwich".into(),
                    version: "2.1.0".into(),
                    config_hash: "cafe".into(),
                },
                block: b,
                txs,
                raw_confidence: Confidence::new(0.9),
                evidence: serde_json::json!({}),
            }),
            secs,
        )
    }

    fn incident(id: IncidentId, txs: Vec<B256>, profit: f64, secs: i64) -> EventEnvelope {
        envelope(
            DomainEvent::IncidentCreated(IncidentCreated {
                incident_id: id,
                alert_id: events::primitives::AlertId::new(),
                kind: AlertKind::Sandwich,
                txs,
                profit,
                victim_loss: 0.0,
                impact_usd: None,
                severity: Severity::High,
                suggested_action: events::primitives::SuggestedAction::Escalate,
                victim_address: None,
                victim_loss_usd: None,
            }),
            secs,
        )
    }

    #[tokio::test]
    async fn another_chains_block_is_commit_skipped_without_touching_the_stores() {
        let h = harness();
        // A Base block on the shared topics (Sprint 13 t2): the Ethereum-only
        // pipeline must commit-skip it — asking the facts RPC would error
        // (`BlockNotYetKnown`) forever and wedge the stream on retries.
        let foreign = EventEnvelope::with_metadata(
            Uuid::new_v4(),
            at(0),
            Chain::BASE,
            DomainEvent::BlockCanonicalized(BlockCanonicalized {
                block: block(7, 0x07),
            }),
        );

        let handled = h.consumer.handle(foreign).await;
        assert_eq!(handled, Handled::Commit);
        assert!(h.store.appended().is_empty(), "no record opened");
        assert!(h.sink.events().is_empty(), "nothing published");
    }

    #[tokio::test]
    async fn canonicalized_block_opens_a_relay_attributed_record_and_mints_a_label() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        h.relays.insert(hash(0x07), attribution());

        let handled = h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;
        assert_eq!(handled, Handled::Commit);

        let appended = h.store.appended();
        assert_eq!(appended.len(), 1);
        let record = &appended[0];
        assert_eq!(record.block, block(7, 0x07));
        assert_eq!(record.fee_recipient, coinbase());
        assert_eq!(record.extra_data, "beaverbuild.org");
        assert_eq!(record.relay.as_ref().unwrap().relay, "flashbots");
        assert_eq!(record.coinbase_transfers.len(), 1);
        // The relay evidence minted a heuristic BuilderAddress label from the
        // graffiti, and the record reads it back as the builder's name.
        assert_eq!(record.builder_label.as_deref(), Some("beaverbuild.org"));
        let stored = h.labels.labels_for(&coinbase(), at(1)).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].kind, LabelKind::BuilderAddress);
        assert_eq!(stored[0].source, LabelSource::Heuristic);
        // ... and announced it on the backbone.
        assert!(h
            .sink
            .events()
            .iter()
            .any(|e| e.event_type() == "LabelAdded"));
    }

    #[tokio::test]
    async fn an_existing_builder_label_is_read_not_re_minted() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        h.relays.insert(hash(0x07), attribution());
        // An operator already named this builder — the strongest claim wins.
        h.labels
            .add_label(&LabelRecord::new(
                coinbase(),
                LabelKind::BuilderAddress,
                "Beaver Build",
                LabelSource::Manual,
                "operator:42",
                at(-100),
            ))
            .await
            .unwrap();

        h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;

        let record = &h.store.appended()[0];
        assert_eq!(record.builder_label.as_deref(), Some("Beaver Build"));
        assert!(
            h.sink.events().is_empty(),
            "no LabelAdded — nothing was minted"
        );
    }

    #[tokio::test]
    async fn without_relay_evidence_no_label_is_minted() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        // No relay attribution mapped: could be an ordinary local validator.

        h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;

        let record = &h.store.appended()[0];
        assert!(record.relay.is_none());
        assert!(record.builder_label.is_none());
        assert!(h
            .labels
            .labels_for(&coinbase(), at(1))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn a_confirmed_incident_folds_into_its_block_through_the_trigger_join() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());

        let tx = hash(0x21);
        h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;
        h.consumer
            .handle(triggered(block(7, 0x07), vec![tx], 1))
            .await;
        let id = IncidentId::new();
        let handled = h.consumer.handle(incident(id, vec![tx], 250.0, 2)).await;
        assert_eq!(handled, Handled::Commit);

        let appended = h.store.appended();
        let last = appended.last().unwrap();
        assert_eq!(last.sandwich_count, 1);
        assert_eq!(last.mev_extracted_usd, 250.0);

        // Retraction (§15) takes exactly that contribution back out.
        h.consumer
            .handle(envelope(
                DomainEvent::IncidentRetracted(IncidentRetracted {
                    incident_id: id,
                    reason: "block reverted".into(),
                }),
                3,
            ))
            .await;
        let last = h.store.appended().last().unwrap().clone();
        assert_eq!(last.sandwich_count, 0);
        assert_eq!(last.mev_extracted_usd, 0.0);
    }

    #[tokio::test]
    async fn a_reverted_block_gets_a_final_reverted_snapshot() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;

        h.consumer
            .handle(envelope(
                DomainEvent::BlockReverted(BlockReverted {
                    block: block(7, 0x07),
                    replaced_by: hash(0x17),
                }),
                1,
            ))
            .await;

        let appended = h.store.appended();
        assert_eq!(appended.len(), 2);
        assert!(appended[1].reverted);
    }

    #[tokio::test]
    async fn an_rpc_blip_leaves_the_offset_for_redelivery() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        h.facts.fail_next();

        let handled = h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;
        assert_eq!(handled, Handled::Retry);
        assert!(h.store.appended().is_empty());

        // The redelivery succeeds.
        let handled = h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;
        assert_eq!(handled, Handled::Commit);
        assert_eq!(h.store.appended().len(), 1);
    }

    #[tokio::test]
    async fn a_block_the_node_does_not_know_yet_is_retried() {
        let h = harness();
        // Nothing mapped: the node is lagging the ingestion service's view.
        let handled = h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;
        assert_eq!(handled, Handled::Retry);
    }

    /// The crux of the pending-writes queue (see the module docs): a fold that
    /// succeeded but whose flush failed must not lose its snapshot to the
    /// redelivery, which the book correctly treats as a duplicate.
    #[tokio::test]
    async fn a_failed_flush_survives_into_the_redelivered_no_op_fold() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        h.store.fail_next();

        let handled = h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;
        assert_eq!(handled, Handled::Retry);
        assert!(h.store.appended().is_empty(), "flush failed");

        // Redelivery: the record is already open (fold no-ops), but the queued
        // snapshot from the failed pass flushes now — nothing is lost.
        let handled = h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;
        assert_eq!(handled, Handled::Commit);
        let appended = h.store.appended();
        assert_eq!(appended.len(), 1);
        assert_eq!(appended[0].block, block(7, 0x07));
    }

    #[tokio::test]
    async fn a_redelivered_incident_does_not_double_count() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        let tx = hash(0x21);
        h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;
        h.consumer
            .handle(triggered(block(7, 0x07), vec![tx], 1))
            .await;

        let id = IncidentId::new();
        h.consumer.handle(incident(id, vec![tx], 250.0, 2)).await;
        let before = h.store.appended().len();
        h.consumer.handle(incident(id, vec![tx], 250.0, 3)).await;

        let appended = h.store.appended();
        assert_eq!(appended.len(), before, "duplicate folded nothing new");
        assert_eq!(appended.last().unwrap().sandwich_count, 1);
    }

    // ── Cross-chain findings (§24, Sprint 17 t4) ──────────────────────

    use events::cross_chain::CrossChainLegRef;

    fn cc_leg(chain: Chain, n: u64, byte: u8) -> CrossChainLegRef {
        CrossChainLegRef {
            chain,
            block: block(n, byte),
            tx: hash(byte),
        }
    }

    fn bridge_finding(
        deposit_leg: CrossChainLegRef,
        fill_leg: CrossChainLegRef,
        profit: f64,
    ) -> BridgeMevDetected {
        BridgeMevDetected {
            finding_id: CrossChainFindingId::new(),
            bridge: "usdc-eth-base".into(),
            deposit_leg,
            fill_leg,
            entity_hint: AccountAddress::repeat_byte(0xaa),
            profit,
            victim_loss: profit * 0.9,
            confidence: Confidence::new(0.8),
            severity: Severity::Medium,
            provisional: true,
        }
    }

    fn cross_chain_mev_finding(legs: Vec<CrossChainLegRef>, profit: f64) -> CrossChainMevDetected {
        CrossChainMevDetected {
            finding_id: CrossChainFindingId::new(),
            kind: AlertKind::Arbitrage,
            bridge: "usdc-eth-base".into(),
            legs,
            entity_hint: AccountAddress::repeat_byte(0xaa),
            profit,
            latency_ms: 2_500,
            confidence: Confidence::new(0.7),
            severity: Severity::Low,
            provisional: true,
        }
    }

    /// Envelope tagged under an explicit chain — unlike [`envelope`] (always
    /// `Chain::ETHEREUM`), used to prove a cross-chain finding is routed by
    /// its *legs*, not by the envelope's own chain (§17's fill-leg/last-leg
    /// convention need not be this pipeline's chain).
    fn envelope_on(payload: DomainEvent, chain: Chain, secs: i64) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), at(secs), chain, payload)
    }

    /// The fill leg lands on this pipeline's chain (Ethereum); the deposit
    /// leg is on Base. Folding proceeds off the *leg*, even though the
    /// envelope itself is tagged Base — the crux of the routing fix.
    #[tokio::test]
    async fn a_bridge_finding_leg_on_this_chain_folds_into_its_open_block() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;

        let finding = bridge_finding(
            cc_leg(Chain::BASE, 900, 0x90),
            cc_leg(Chain::ETHEREUM, 7, 0x07),
            500.0,
        );
        let handled = h
            .consumer
            .handle(envelope_on(
                DomainEvent::BridgeMevDetected(finding),
                Chain::BASE,
                1,
            ))
            .await;
        assert_eq!(handled, Handled::Commit);

        let last = h.store.appended().last().unwrap().clone();
        assert_eq!(last.cross_chain_bridge_count, 1);
        assert_eq!(last.cross_chain_provisional_usd, 500.0);
        assert_eq!(
            last.cross_chain_arb_count, 0,
            "not double-counted as an arb"
        );
    }

    /// Neither leg is on this pipeline's chain: nothing is folded, and the
    /// consumer doesn't error trying to open a block it was never asked to
    /// canonicalize.
    #[tokio::test]
    async fn a_finding_with_no_leg_on_this_chain_is_ignored() {
        let h = harness();
        let finding = cross_chain_mev_finding(
            vec![
                cc_leg(Chain::BASE, 900, 0x90),
                cc_leg(Chain(999), 901, 0x91),
            ],
            250.0,
        );

        let handled = h
            .consumer
            .handle(envelope_on(
                DomainEvent::CrossChainMevDetected(finding),
                Chain::BASE,
                1,
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(h.store.appended().is_empty());
    }

    /// A finding leg that arrives before its block's record is buffered, then
    /// folds once the canonicalization opens the record (mirrors the incident
    /// buffering behaviour).
    #[tokio::test]
    async fn a_finding_leg_buffers_until_its_block_opens() {
        let h = harness();
        let finding = cross_chain_mev_finding(
            vec![
                cc_leg(Chain::ETHEREUM, 7, 0x07),
                cc_leg(Chain::BASE, 900, 0x90),
            ],
            250.0,
        );

        let handled = h
            .consumer
            .handle(envelope_on(
                DomainEvent::CrossChainMevDetected(finding),
                Chain::BASE,
                1,
            ))
            .await;
        assert_eq!(handled, Handled::Commit);
        assert!(h.store.appended().is_empty(), "buffered, not lost");

        h.facts.insert(hash(0x07), facts_with_tip());
        h.consumer.handle(canonicalized(block(7, 0x07), 2)).await;

        let last = h.store.appended().last().unwrap().clone();
        assert_eq!(last.cross_chain_arb_count, 1);
        assert_eq!(last.cross_chain_provisional_usd, 250.0);
    }

    /// `CrossChainFindingRetracted` subtracts exactly what the finding added
    /// on this chain (§15/§24).
    #[tokio::test]
    async fn cross_chain_finding_retraction_subtracts_what_it_added() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;

        let finding = bridge_finding(
            cc_leg(Chain::BASE, 900, 0x90),
            cc_leg(Chain::ETHEREUM, 7, 0x07),
            500.0,
        );
        let finding_id = finding.finding_id;
        h.consumer
            .handle(envelope_on(
                DomainEvent::BridgeMevDetected(finding),
                Chain::BASE,
                1,
            ))
            .await;

        let handled = h
            .consumer
            .handle(envelope_on(
                DomainEvent::CrossChainFindingRetracted(CrossChainFindingRetracted {
                    finding_id,
                    reason: "leg block reverted".into(),
                }),
                Chain::BASE,
                2,
            ))
            .await;
        assert_eq!(handled, Handled::Commit);

        let last = h.store.appended().last().unwrap().clone();
        assert_eq!(last.cross_chain_bridge_count, 0);
        assert_eq!(last.cross_chain_provisional_usd, 0.0);
    }

    /// A redelivered finding leg does not double-count (§4/§7 idempotency).
    #[tokio::test]
    async fn a_redelivered_finding_leg_does_not_double_count() {
        let h = harness();
        h.facts.insert(hash(0x07), facts_with_tip());
        h.consumer.handle(canonicalized(block(7, 0x07), 0)).await;

        let finding = bridge_finding(
            cc_leg(Chain::BASE, 900, 0x90),
            cc_leg(Chain::ETHEREUM, 7, 0x07),
            500.0,
        );
        h.consumer
            .handle(envelope_on(
                DomainEvent::BridgeMevDetected(finding.clone()),
                Chain::BASE,
                1,
            ))
            .await;
        h.consumer
            .handle(envelope_on(
                DomainEvent::BridgeMevDetected(finding),
                Chain::BASE,
                2,
            ))
            .await;

        let last = h.store.appended().last().unwrap().clone();
        assert_eq!(
            last.cross_chain_bridge_count, 1,
            "redelivery didn't double-count"
        );
        assert_eq!(last.cross_chain_provisional_usd, 500.0);
    }
}
