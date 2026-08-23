//! Cross-chain attribution (§8, Sprint 17 t4) — feeds `BridgeMevDetected`/
//! `CrossChainMevDetected` (§24) into the same entity-clustering + association-
//! flywheel machinery [`crate::attribution`] built for single-chain incidents,
//! so a shared `entity_hint` address observed across two or more chains
//! resolves to **one** entity instead of a separate per-chain identity. This
//! is the flywheel (§8.6) made cross-chain: entity clustering still
//! auto-generates labels, labels still improve attribution confidence, better
//! attribution still surfaces more entity links — the only thing new is that
//! the *trigger* can now be a correlated cross-chain finding instead of a
//! confirmed same-chain incident.
//!
//! ## `entity_hint` stays a correlation hint, not a label
//!
//! `BridgeMevDetected`/`CrossChainMevDetected::entity_hint` is a behaviour-
//! derived fact (a shared funder/profit-receiver/bridge-recipient observed
//! on-chain, per its own docs in `events::cross_chain`) — never itself turned
//! into a `Label`. This consumer only ever uses it the way [`crate::attribution`]
//! uses any incident address: as the **seed** for [`cluster_address`], the
//! same §8.2 graph walk every other entity-clustering pass runs. No code path
//! here mints a label naming `entity_hint` "cross-chain-correlated" or
//! similar; the only labels this consumer can produce are the association
//! flywheel's ordinary derived `ScammerAssociate` labels on an *already*
//! flagged entity's cluster-mates — the exact same mechanism, and the exact
//! same restraint, [`crate::attribution::Attributor`] applies to incident
//! addresses.
//!
//! ## Why each leg's own chain matters
//!
//! A cross-chain finding's legs each carry their own `chain` (§24 —
//! `CrossChainLegRef`), and [`cluster_address`]'s graph walk is chain-scoped
//! (adjacency facts are chain-partitioned, §14). Entity *ownership*, by
//! contrast, is keyed by address alone ([`crate::store::EntityStore::entity_for_address`])
//! — chain-agnostic. So walking `entity_hint` once per distinct leg chain
//! (not once, and not per-leg-with-its-own-entity) is exactly what "links
//! legs to one entity across chains" means mechanically: the first chain's
//! walk seeds (or finds) the entity, every subsequent chain's walk discovers
//! that `entity_hint` already owns it and simply contributes *that chain's*
//! cluster-relevant neighbours as new members of the same entity — a bridge
//! deposit's chain-A funding cluster and its fill's chain-B funding cluster
//! converge on one [`EntityId`] instead of staying two islands.
//!
//! ## No `PreliminaryAlertCreated`-style buffering
//!
//! Unlike `IncidentCreated` (whose addresses live on a separate,
//! possibly-reordered `PreliminaryAlertCreated`, §2), `entity_hint` and every
//! leg's `chain` arrive directly on the triggering event — there is no second
//! topic to correlate against, so this consumer needs none of
//! [`crate::attribution::Attributor`]'s pending-address buffering.
//!
//! ## Deliberately not consumed: `CrossChainFindingRetracted`
//!
//! Every `cluster_address` call this consumer makes passes `incident_id:
//! None` — the same "operator-driven clustering" branch [`crate::cluster`]
//! documents, meaning these merges are **never** candidates for the §15
//! reorg-rollback [`crate::reorg`] runs off `IncidentRetracted`. A later
//! `CrossChainFindingRetracted` (withdrawing the *finding* because one leg's
//! block reverted, §24 Sprint 17 t3) does not reverse the entity merge this
//! consumer already made from it: the underlying graph fact — `entity_hint`
//! funded/deployed/received-profit-from another address, observed on-chain —
//! doesn't stop being true just because the specific bridge-MEV/arb estimate
//! built on top of it got retracted. Reversing real graph facts on a
//! provisional-estimate retraction would be inventing a correction this
//! consumer has no evidence for; see [`crate::attribution`]'s own module docs
//! for the identical stance on which events do and don't get to unwind a merge.
//!
//! ## No dedicated attribution-audit row
//!
//! Incident attribution persists an `AttributionRecord` (Postgres
//! `attributions`, keyed `(incident_id, entity_id)`) so "every incident this
//! entity is behind" is a query. This consumer deliberately does not add a
//! parallel `(finding_id, entity_id)` table: the finding→entity link is
//! already durably auditable via the `evidence` string every `cluster_address`
//! write carries (`"cross_chain_finding:{finding_id}"`, landing in
//! `entity_addresses.evidence`/`entity_merges.evidence_ref`) — a real, queryable
//! trail, just not a dedicated index. A "every cross-chain finding behind this
//! entity" read path is a documented future option if that query pattern
//! shows up, not a gap in today's auditability.
//!
//! ## Idempotency (§4/§7)
//!
//! Identical to [`crate::attribution`]: `cluster_address` is idempotent, the
//! association flywheel's derived labels use a deterministic id, and
//! `SanctionHit` is re-emitted on every redelivery (a hard alert restating
//! current state is truthful, not something to suppress).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{publish_resilient, run_consumer, EventHandler, EventSink, Handled, Transience};
use events::intelligence::{EntityCreated, EntityMerged, LabelAdded, SanctionHit};
use events::primitives::{AccountAddress, Chain, CrossChainFindingId, EntityId};
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;

use crate::adjacency::AdjacencyStore;
use crate::association::{self, AssociationError};
use crate::cache::HotCache;
use crate::cluster::{cluster_address, ClusterError, ClusterLimits, ClusterSeams};
use crate::merge_actor::MergeActorHandle;
use crate::store::{StoreError, StoreSeams};

/// The two cross-chain finding types this consumer subscribes to. An
/// explicit, closed list (not a `mev.events.*` regex) so a renamed/missing
/// topic fails loudly — the same discipline as every other consumer on the
/// backbone. `CrossChainFindingRetracted` is deliberately excluded — see the
/// module docs.
const CONSUMED_EVENT_TYPES: &[&str] = &["BridgeMevDetected", "CrossChainMevDetected"];

/// The topics the consumer subscribes to (one per [`CONSUMED_EVENT_TYPES`] entry).
pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build the consumer. Manual offset commit (`enable.auto.commit=false`) ties
/// the commit to a fully-processed pass; `earliest` means a fresh group
/// attributes from the start of retained history (cf. the attribution
/// consumer).
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "cross-chain-attribution")
}

/// A failure attributing one finding. Wraps every seam's error and forwards
/// the shared retry/skip decision (§4): a transient fault leaves the offset
/// for redelivery (every write here is idempotent, so a retry converges); a
/// permanent one is logged and skipped so one poison finding can't wedge the
/// stream.
#[derive(Debug, thiserror::Error)]
pub enum CrossChainAttributionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Cluster(#[from] ClusterError),
    #[error(transparent)]
    Association(#[from] AssociationError),
}

impl Transience for CrossChainAttributionError {
    /// Whether retrying the same finding could plausibly succeed.
    fn is_transient(&self) -> bool {
        match self {
            CrossChainAttributionError::Store(err) => err.is_transient(),
            CrossChainAttributionError::Cluster(err) => err.is_transient(),
            CrossChainAttributionError::Association(err) => err.is_transient(),
        }
    }
}

/// The cross-chain attribution consumer: the store/graph/cache seams this
/// pass touches, plus the event sink it publishes discovered facts to and the
/// merge actor that serializes its `cluster_address` calls against every
/// other in-process caller (§17 — this process's own, since `main.rs` runs
/// this as its own independently deployable subcommand, mirroring
/// `attribute`/`score`/`reorg`/`block-production`).
pub struct CrossChainAttributor {
    stores: StoreSeams,
    graph: Arc<dyn AdjacencyStore>,
    cache: Arc<dyn HotCache>,
    sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    publish_backoff: Duration,
    cluster_limits: ClusterLimits,
    merge_actor: MergeActorHandle,
}

impl CrossChainAttributor {
    /// Build the consumer over its seams. `shutdown` aborts publish-retry
    /// loops for a graceful drain, the same seam every other consumer on the
    /// backbone takes.
    pub fn new(
        stores: StoreSeams,
        graph: Arc<dyn AdjacencyStore>,
        cache: Arc<dyn HotCache>,
        sink: Arc<dyn EventSink>,
        shutdown: CancellationToken,
        merge_actor: MergeActorHandle,
    ) -> Self {
        Self {
            stores,
            graph,
            cache,
            sink,
            shutdown,
            publish_backoff: event_bus::PUBLISH_BACKOFF,
            cluster_limits: ClusterLimits::default(),
            merge_actor,
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
            "cross-chain-attribution",
            retry_backoff,
            dlq,
            self,
            shutdown,
        )
        .await
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

    /// Attribute one cross-chain finding (see the module docs for the full
    /// pass): a sanctions check on `entity_hint` (§8.5, independent of
    /// clustering), then [`cluster_address`] once per distinct leg chain so
    /// each chain's cluster-relevant neighbours converge on the same entity,
    /// then the association flywheel once against whatever entity was
    /// resolved. `envelope_chain` is only where discovered events get
    /// published under — the graph walk itself is chain-scoped per `chains`.
    #[tracing::instrument(skip_all, fields(finding_id = %finding_id, chains = chains.len()))]
    async fn attribute(
        &self,
        finding_id: CrossChainFindingId,
        entity_hint: AccountAddress,
        chains: Vec<Chain>,
        envelope_chain: Chain,
        at: DateTime<Utc>,
    ) -> Result<(), CrossChainAttributionError> {
        for entry in self.stores.sanctions.sanction_matches(&entity_hint).await? {
            self.publish(
                envelope_chain,
                DomainEvent::SanctionHit(SanctionHit {
                    address: entity_hint,
                    list: entry.list_name,
                    entry: entry.entry,
                }),
            )
            .await;
        }

        let evidence = format!("cross_chain_finding:{finding_id}");
        let mut resolved_entity: Option<EntityId> = None;
        for chain in chains {
            let Some(outcome) = cluster_address(
                ClusterSeams {
                    graph: self.graph.as_ref(),
                    entities: self.stores.entities.as_ref(),
                    merge_actor: &self.merge_actor,
                },
                chain,
                &entity_hint,
                &evidence,
                // Never a candidate for §15 reorg rollback — see the module
                // docs on `CrossChainFindingRetracted`.
                None,
                at,
                self.cluster_limits,
            )
            .await?
            else {
                // entity_hint is itself an infrastructure hub on this chain
                // (§8.2) — no cluster to form here; another leg's chain may
                // still resolve one.
                continue;
            };

            if let Some(seed) = outcome.created_seed {
                self.publish(
                    envelope_chain,
                    DomainEvent::EntityCreated(EntityCreated {
                        entity_id: outcome.entity_id,
                        seed_address: seed,
                    }),
                )
                .await;
            }
            for absorbed in &outcome.absorbed {
                self.publish(
                    envelope_chain,
                    DomainEvent::EntityMerged(EntityMerged {
                        surviving_id: outcome.entity_id,
                        absorbed_id: *absorbed,
                        evidence_ref: evidence.clone(),
                    }),
                )
                .await;
            }
            resolved_entity = Some(outcome.entity_id);
        }

        let Some(entity_id) = resolved_entity else {
            return Ok(());
        };
        let newly_stored =
            association::label_associates(&self.stores, self.cache.as_ref(), entity_id, at).await?;
        for derived in newly_stored {
            self.publish(
                envelope_chain,
                DomainEvent::LabelAdded(LabelAdded {
                    address: derived.address,
                    kind: <&str>::from(derived.kind).to_owned(),
                    value: derived.value.clone(),
                    confidence: derived.confidence,
                    source: <&str>::from(derived.source).to_owned(),
                }),
            )
            .await;
        }
        Ok(())
    }

    /// Attribute, then translate the outcome into the offset action — the
    /// same transient-retries/permanent-skips/shutdown-aware pattern
    /// [`crate::attribution::Attributor::dispatch`] uses.
    async fn dispatch(
        &self,
        finding_id: CrossChainFindingId,
        entity_hint: AccountAddress,
        chains: Vec<Chain>,
        envelope_chain: Chain,
        at: DateTime<Utc>,
    ) -> Handled {
        match self
            .attribute(finding_id, entity_hint, chains, envelope_chain, at)
            .await
        {
            Ok(()) if self.shutdown.is_cancelled() => Handled::Stop,
            Ok(()) => Handled::Commit,
            Err(err) => event_bus::handled(err, "cross-chain-attribution"),
        }
    }
}

/// Deduplicate a finding's leg chains into a deterministic, sorted order — so
/// a redelivered finding walks its chains in the same order every time
/// (`chains` isn't itself part of any idempotency key, but a stable order
/// keeps traces/logs comparable across runs).
fn distinct_chains(chains: impl IntoIterator<Item = Chain>) -> Vec<Chain> {
    let unique: HashSet<Chain> = chains.into_iter().collect();
    let mut sorted: Vec<Chain> = unique.into_iter().collect();
    sorted.sort_by_key(|chain| chain.0);
    sorted
}

#[async_trait]
impl EventHandler for CrossChainAttributor {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        let at = envelope.occurred_at;
        let envelope_chain = envelope.chain;
        match envelope.payload {
            DomainEvent::BridgeMevDetected(finding) => {
                let chains = distinct_chains([finding.deposit_leg.chain, finding.fill_leg.chain]);
                self.dispatch(
                    finding.finding_id,
                    finding.entity_hint,
                    chains,
                    envelope_chain,
                    at,
                )
                .await
            }
            DomainEvent::CrossChainMevDetected(finding) => {
                let chains = distinct_chains(finding.legs.iter().map(|leg| leg.chain));
                self.dispatch(
                    finding.finding_id,
                    finding.entity_hint,
                    chains,
                    envelope_chain,
                    at,
                )
                .await
            }
            other => {
                tracing::warn!(
                    event = other.event_type(),
                    "unexpected event on cross-chain-attribution topics; skipping"
                );
                Handled::Commit
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_actor::MergeActor;
    use crate::model::{
        AdjacencyEdge, EdgeKind, LabelKind, LabelRecord, LabelSource, SanctionEntry,
    };
    use crate::store::{EntityStore, LabelStore, SanctionsStore};
    use crate::test_util::{
        store_seams, InMemoryAdjacency, InMemoryHotCache, InMemoryIntelligenceStore,
    };
    use alloy_primitives::{Address, B256};
    use event_bus::test_util::RecordingSink;
    use events::cross_chain::{BridgeMevDetected, CrossChainLegRef, CrossChainMevDetected};
    use events::primitives::{AlertKind, BlockRef, Confidence, Severity};
    use uuid::Uuid;

    fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    fn hash(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn block(n: u64, byte: u8) -> BlockRef {
        BlockRef::new(n, hash(byte))
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    fn envelope(payload: DomainEvent, at: DateTime<Utc>) -> EventEnvelope {
        EventEnvelope::with_metadata(Uuid::new_v4(), at, Chain::ETHEREUM, payload)
    }

    fn leg(chain: Chain, n: u64, byte: u8) -> CrossChainLegRef {
        CrossChainLegRef {
            chain,
            block: block(n, byte),
            tx: hash(byte),
        }
    }

    fn bridge_finding(entity_hint: AccountAddress) -> BridgeMevDetected {
        BridgeMevDetected {
            finding_id: CrossChainFindingId::new(),
            bridge: "usdc-eth-base".into(),
            deposit_leg: leg(Chain::ETHEREUM, 100, 0x01),
            fill_leg: leg(Chain::BASE, 200, 0x02),
            entity_hint,
            profit: 1_000.0,
            victim_loss: 900.0,
            confidence: Confidence::new(0.8),
            severity: Severity::Medium,
            provisional: true,
        }
    }

    fn cross_chain_mev_finding(entity_hint: AccountAddress) -> CrossChainMevDetected {
        CrossChainMevDetected {
            finding_id: CrossChainFindingId::new(),
            kind: AlertKind::Arbitrage,
            bridge: "usdc-eth-base".into(),
            legs: vec![leg(Chain::ETHEREUM, 100, 0x01), leg(Chain::BASE, 200, 0x02)],
            entity_hint,
            profit: 500.0,
            latency_ms: 2_500,
            confidence: Confidence::new(0.7),
            severity: Severity::Low,
            provisional: true,
        }
    }

    struct Harness {
        attributor: CrossChainAttributor,
        sink: Arc<RecordingSink>,
        store: Arc<InMemoryIntelligenceStore>,
    }

    fn harness_with_graph(graph: InMemoryAdjacency) -> Harness {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let sink = Arc::new(RecordingSink::default());
        let attributor = CrossChainAttributor::new(
            store_seams(&store),
            Arc::new(graph),
            Arc::new(InMemoryHotCache::new()),
            sink.clone(),
            CancellationToken::new(),
            MergeActor::spawn(),
        );
        Harness {
            attributor,
            sink,
            store,
        }
    }

    fn harness() -> Harness {
        harness_with_graph(InMemoryAdjacency::new())
    }

    fn is_entity_created(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::EntityCreated(_))
    }
    fn is_entity_merged(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::EntityMerged(_))
    }
    fn is_sanction_hit(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::SanctionHit(_))
    }
    fn is_label_added(e: &DomainEvent) -> bool {
        matches!(e, DomainEvent::LabelAdded(_))
    }

    /// A fresh `entity_hint` with no prior entity/adjacency seeds exactly one
    /// entity — the second leg's chain finds the address already owned, so it
    /// contributes nothing further (idempotent re-walk, not a second create).
    #[tokio::test]
    async fn a_fresh_entity_hint_seeds_one_entity_from_a_bridge_finding() {
        let h = harness();
        let hint = addr(1);

        h.attributor
            .handle(envelope(
                DomainEvent::BridgeMevDetected(bridge_finding(hint)),
                at(5),
            ))
            .await;

        assert_eq!(h.sink.count(is_entity_created), 1, "seeded exactly once");
        let entity_id = h
            .store
            .entity_for_address(&hint)
            .await
            .unwrap()
            .expect("entity_hint now owns an entity");
        let entity = h.store.entity(entity_id).await.unwrap().unwrap();
        assert_eq!(entity.addresses, vec![hint]);
    }

    /// The headline behaviour (§8, Sprint 17 t4): `entity_hint` funds a
    /// different address on *each* leg's own chain. Walking both legs' chains
    /// converges both chain-local funding clusters onto the same entity — the
    /// concrete meaning of "legs link to one entity across chains".
    #[tokio::test]
    async fn legs_on_different_chains_link_to_one_entity() {
        let hint = addr(1);
        let eth_associate = addr(2);
        let base_associate = addr(3);

        let graph = InMemoryAdjacency::new();
        graph
            .append(&[
                AdjacencyEdge {
                    chain: Chain::ETHEREUM,
                    src: hint,
                    dst: eth_associate,
                    kind: EdgeKind::Funded,
                    evidence: "0xeth".into(),
                    block_number: 100,
                    observed_at: at(1),
                },
                AdjacencyEdge {
                    chain: Chain::BASE,
                    src: hint,
                    dst: base_associate,
                    kind: EdgeKind::Funded,
                    evidence: "0xbase".into(),
                    block_number: 200,
                    observed_at: at(1),
                },
            ])
            .await
            .unwrap();
        let h = harness_with_graph(graph);

        h.attributor
            .handle(envelope(
                DomainEvent::CrossChainMevDetected(cross_chain_mev_finding(hint)),
                at(10),
            ))
            .await;

        let entity_id = h
            .store
            .entity_for_address(&hint)
            .await
            .unwrap()
            .expect("entity resolved");
        let entity = h.store.entity(entity_id).await.unwrap().unwrap();
        let mut members = entity.addresses.clone();
        members.sort();
        let mut expected = vec![hint, eth_associate, base_associate];
        expected.sort();
        assert_eq!(
            members, expected,
            "chain-A's and chain-B's funding clusters both landed on one entity"
        );
    }

    /// A sanctioned `entity_hint` emits `SanctionHit` immediately (§8.5),
    /// independent of whatever clustering finds.
    #[tokio::test]
    async fn a_sanctioned_entity_hint_emits_sanction_hit() {
        let h = harness();
        let hint = addr(1);
        h.store
            .seed_sanctions(&[SanctionEntry {
                address: hint,
                list_name: "ofac_sdn".into(),
                entry: "OFAC SDN digital-currency address".into(),
                listed_at: None,
            }])
            .await
            .unwrap();

        h.attributor
            .handle(envelope(
                DomainEvent::BridgeMevDetected(bridge_finding(hint)),
                at(5),
            ))
            .await;

        assert_eq!(h.sink.count(is_sanction_hit), 1);
    }

    /// The association flywheel (§8.1/§8.6) fires off a cross-chain-resolved
    /// entity exactly like it does off an incident-resolved one, and a
    /// redelivered finding does not re-emit the derived label.
    #[tokio::test]
    async fn association_flywheel_labels_cluster_mates_from_a_cross_chain_entity() {
        let hint = addr(1);
        let associate = addr(2);

        let scammer = LabelRecord::new(
            hint,
            LabelKind::KnownScammer,
            "known scammer",
            LabelSource::Manual,
            "operator",
            at(1),
        );

        let graph = InMemoryAdjacency::new();
        graph
            .append(&[AdjacencyEdge {
                chain: Chain::ETHEREUM,
                src: hint,
                dst: associate,
                kind: EdgeKind::Funded,
                evidence: "0xeth".into(),
                block_number: 100,
                observed_at: at(1),
            }])
            .await
            .unwrap();
        let h = harness_with_graph(graph);
        h.store.add_label(&scammer).await.unwrap();

        let finding = bridge_finding(hint);
        h.attributor
            .handle(envelope(
                DomainEvent::BridgeMevDetected(finding.clone()),
                at(5),
            ))
            .await;

        assert_eq!(h.sink.count(is_label_added), 1);
        let labels = h.store.labels_for(&associate, at(1_000)).await.unwrap();
        assert!(labels.iter().any(
            |l| l.kind == LabelKind::ScammerAssociate && l.source == LabelSource::EntityDerived
        ));

        // Redelivery (same finding, e.g. an at-least-once replay) must not
        // duplicate the derived label.
        h.attributor
            .handle(envelope(DomainEvent::BridgeMevDetected(finding), at(6)))
            .await;
        assert_eq!(h.sink.count(is_label_added), 1, "idempotent re-run");
    }

    /// Two addresses already owned by two different entities, unified by an
    /// adjacency signal reachable from `entity_hint` on one leg's chain,
    /// merge into one entity — `EntityMerged` fires.
    #[tokio::test]
    async fn clustering_merges_pre_existing_entities_reachable_from_a_leg_chain() {
        let hint = addr(1);
        let other = addr(2);

        let store = InMemoryIntelligenceStore::new();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        store
            .create_entity(e1, &hint, "prior", at(1))
            .await
            .unwrap();
        store
            .create_entity(e2, &other, "prior", at(1))
            .await
            .unwrap();

        let graph = InMemoryAdjacency::new();
        graph
            .append(&[AdjacencyEdge {
                chain: Chain::ETHEREUM,
                src: hint,
                dst: other,
                kind: EdgeKind::Funded,
                evidence: "0xeth".into(),
                block_number: 100,
                observed_at: at(1),
            }])
            .await
            .unwrap();
        let sink = Arc::new(RecordingSink::default());
        let store = Arc::new(store);
        let attributor = CrossChainAttributor::new(
            store_seams(&store),
            Arc::new(graph),
            Arc::new(InMemoryHotCache::new()),
            sink.clone(),
            CancellationToken::new(),
            MergeActor::spawn(),
        );

        attributor
            .handle(envelope(
                DomainEvent::BridgeMevDetected(bridge_finding(hint)),
                at(5),
            ))
            .await;

        assert_eq!(sink.count(is_entity_merged), 1);
    }
}
