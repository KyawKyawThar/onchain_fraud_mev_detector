//! The clustering-signal consumer (§20.3, Sprint 19 t3): `AddressEmbeddingUpdated`
//! in, [`LinkCandidate`](crate::link_candidate::LinkCandidate) proposals and
//! `EntityLinkProposed`/`LabelAdded` out.
//!
//! [`crate::link_candidate`] owns the *decision*; this module owns everything
//! around it — which recomputations are worth a search at all, one batched read
//! of the truth the decision needs, and the at-least-once write discipline the
//! rest of the service follows.
//!
//! # Why it hangs off the embedding stream
//!
//! A behavioral link becomes visible exactly when a vector moves, and
//! [`crate::embedding_job`] already publishes precisely that, already
//! deduplicated (a recomputation that changed nothing is skipped, not
//! republished). Running the signal off its own schedule would re-derive that
//! same "what changed" question against the same table, worse. So the event
//! *is* the trigger, and the sweep's staleness bound is inherited for free.
//!
//! # The searches this refuses to run
//!
//! The similarity search is the most expensive read the platform serves, and
//! the embedding sweep recomputes the entire address space on a schedule.
//! Naively pairing them is a self-inflicted denial of service: one sweep lap
//! becomes one ANN scan per address. Four gates stand in front of it, cheapest
//! first, and three of them need no store read at all:
//!
//! 1. **Wrong chain** — this instance embeds and searches one chain's
//!    population (the [`crate::embedding_job`] rule); another chain's events on
//!    the shared topic are committed and skipped.
//! 2. **Wrong feature space** — a vector under a different `embedding_version`,
//!    or under the *same* version name with a different `schema_hash`, is not
//!    comparable to this node's population and is never silently ranked
//!    against it.
//! 3. **No signal** — an all-zero vector has no direction to search along, so
//!    the search would be refused one layer down anyway. Caught off the
//!    payload the event already carries.
//! 4. **Already clustered** — under [`SearchScope::UnclusteredOnly`] (the
//!    default), an address the graph has already placed is skipped. This
//!    is the gate that actually bounds the cost, and it is also the honest
//!    reading of the task: the signal exists to widen recall for addresses
//!    *evidence cannot reach*. Turning it off makes every clustered address a
//!    merge-candidate search too — a real capability, and one an operator
//!    should have to ask for by name.
//!
//! # The loop that terminates
//!
//! A proposal can mint a `ScammerAssociate` label; the label invalidates the
//! subject's embedding; the recomputed embedding lands right back here. That
//! cycle is deliberate — the flywheel (§8.5) — and it terminates because every
//! step is keyed on content rather than time: the label id is
//! [`seeded`](crate::seed::seeded_label_id) from the claim, so the second write
//! is a no-op that publishes nothing; the proposal id is seeded from the
//! address pair, so the second proposal is a `Refreshed` that announces
//! nothing; and the embedding job only republishes a vector that actually
//! moved. Nothing here is allowed to publish on a re-run, and that is what
//! makes the cycle a fixpoint rather than a spiral.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use event_bus::dlq::DeadLetterQueue;
use event_bus::lag::{build_reporting_consumer, LagReporting};
use event_bus::{publish_resilient, run_consumer, EventHandler, EventSink, Handled, Transience};
use events::intelligence::{AddressEmbeddingUpdated, EntityLinkProposed, LabelAdded, LinkFactor};
use events::primitives::{AccountAddress, Chain};
use events::{DomainEvent, EventEnvelope};
use rdkafka::consumer::StreamConsumer;
use tokio_util::sync::CancellationToken;

use crate::association::FLAGGED_KINDS;
use crate::baseline_cache::BaselineSnapshot;
use crate::cache::{CacheError, HotCache};
use crate::embedding::BehaviorSchema;
use crate::embedding_store::EmbeddingStore;
use crate::link_candidate::{
    plan, propose, Effect, LinkCandidateStore, Proposal, ProposalInputs, ProposalOutcome,
    SignalPolicy, PROPOSALS_TOTAL, SUPPRESSED_TOTAL,
};
use crate::similarity::{self, SearchRequest, SimilarityError, SimilarityLimits};
use crate::store::{StoreError, StoreSeams};

/// The one event type this consumer reads. A closed list (not a `mev.events.*`
/// pattern), the same discipline every consumer on the backbone follows.
///
/// Deliberately *only* the embedding stream: the label/entity events that
/// would also change an answer here already reach the embedding job, which
/// republishes the vector they moved. Subscribing to them directly would run
/// the expensive search twice for one change.
pub const CONSUMED_EVENT_TYPES: &[&str] = &["AddressEmbeddingUpdated"];

/// Subjects counted by what the pass did with them: `searched`, or one of the
/// gate labels from [`Skipped`].
pub const SUBJECTS_TOTAL: &str = "intelligence_link_signal_subjects_total";

/// Proposals announced by the recovery sweep rather than by a delivery —
/// events that a redelivery would never have produced.
///
/// **Any non-zero value here is worth reading a log for.** It means a proposal
/// was durably stored and its announcement was lost by something redelivery
/// could not fix, which is a narrower and more interesting failure than the
/// ordinary crash the `re_announce` outcome covers.
pub const RECOVERED_TOTAL: &str = "intelligence_link_signal_recovered_total";

/// The topics the consumer subscribes to (one per [`CONSUMED_EVENT_TYPES`]).
pub fn consumed_topics() -> Vec<String> {
    events::topics_for(CONSUMED_EVENT_TYPES)
}

/// Build the consumer. Manual offset commit ties the commit to a fully
/// proposed-and-published pass, the same as this service's other consumers;
/// `earliest` means a fresh group re-derives proposals from retained history
/// (idempotent by construction — see the module docs).
pub fn build_consumer(brokers: &str, group_id: &str) -> Result<StreamConsumer<LagReporting>> {
    build_reporting_consumer(brokers, group_id, "link_signal")
}

/// Why a subject was not searched. A closed vocabulary: it is a metric label,
/// and the ratios between these are the whole operational picture of what the
/// signal is costing and covering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Skipped {
    /// Another chain's event on the shared topic.
    ForeignChain,
    /// A different `embedding_version`, or the same name over a different
    /// schema hash — not comparable to this node's population.
    ForeignSchema,
    /// An all-zero vector: nothing to match on.
    NoSignal,
    /// The graph already placed this address and the scope is
    /// [`SearchScope::UnclusteredOnly`].
    AlreadyClustered,
    /// The subject has no stored vector under this version — a race between
    /// the event and the ClickHouse write, or a retention gap.
    NotEmbedded,
    /// The population baseline for this `(chain, version)` has not been
    /// computed yet, so nothing can be ranked in the right units. Counted
    /// rather than failed: it resolves when the `embedding-baseline` run mode
    /// next runs, and wedging the consumer until then would help no one.
    NoBaseline,
}

impl Skipped {
    fn label(self) -> &'static str {
        self.into()
    }
}

/// Which subjects a pass is willing to spend a search on.
///
/// A named choice rather than a `bool`: at the call site
/// `scope == SearchScope::UnclusteredOnly` says what it means, where
/// `only_unclustered` said only what it was called — and this is the knob that
/// decides whether the signal costs one ANN scan per *unplaced* address or one
/// per address, which is a difference an operator must be able to read at a
/// glance in config, in logs and in the env docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum SearchScope {
    /// Only addresses the entity graph has not already placed (the default).
    /// The signal exists to widen recall where evidence cannot reach.
    UnclusteredOnly,
    /// Every subject, clustered or not — merge-candidate mode. A real
    /// capability, and one an operator turns on by name after looking at what
    /// the default already costs.
    All,
}

/// Operator-tunable bounds for the pass, beside [`SignalPolicy`]'s
/// proposal-shaping ones.
#[derive(Debug, Clone, Copy)]
pub struct LinkSignalPolicy {
    /// Which subjects earn a search — the cost gate. See [`SearchScope`].
    pub scope: SearchScope,
    /// How many neighbours each search asks for. Small on purpose: the
    /// proposals are capped at [`SignalPolicy::max_per_subject`] anyway, and a
    /// wider ranking here buys nothing but ClickHouse time.
    pub neighbors: u32,
    /// The proposal-shaping policy (threshold, cap, confidence band).
    pub proposal: SignalPolicy,
}

impl Default for LinkSignalPolicy {
    fn default() -> Self {
        Self {
            scope: SearchScope::UnclusteredOnly,
            neighbors: 10,
            proposal: SignalPolicy::default(),
        }
    }
}

/// A failure evaluating one subject. Wraps the three seam errors the pass
/// touches and forwards their retry/skip classification unchanged.
#[derive(Debug, thiserror::Error)]
pub enum LinkSignalError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Cache(#[from] CacheError),
    #[error(transparent)]
    Similarity(#[from] SimilarityError),
}

impl Transience for LinkSignalError {
    fn is_transient(&self) -> bool {
        match self {
            LinkSignalError::Store(err) => err.is_transient(),
            LinkSignalError::Cache(err) => err.is_transient(),
            LinkSignalError::Similarity(err) => err.is_transient(),
        }
    }
}

/// The seams one pass reads and writes.
#[derive(Clone)]
pub struct LinkSignalSeams {
    /// Labels (the anchor evidence, and the derived label's destination) and
    /// entities (the authoritative membership the proposal is judged against).
    pub stores: StoreSeams,
    pub links: Arc<dyn LinkCandidateStore>,
    pub embeddings: Arc<dyn EmbeddingStore>,
    /// Evicted for any address a derived label newly lands on — the §8 hot
    /// cache's correctness comes from explicit eviction, not its TTL.
    pub cache: Arc<dyn HotCache>,
    pub sink: Arc<dyn EventSink>,
    /// The process-wide population baseline snapshot (see
    /// [`crate::baseline_cache`]) — the same shared, timer-refreshed value the
    /// gRPC read path uses, for the same reason: it is keyed by
    /// `(chain, version)`, so a per-event read would buy one round trip and one
    /// failure mode per event for identical bytes.
    pub baseline: Arc<BaselineSnapshot>,
}

/// What one [`LinkSignal::evaluate`] pass did — returned rather than only
/// counted so a test can assert on the decision instead of on a metric.
#[derive(Debug, Clone, PartialEq)]
pub struct SignalOutcome {
    /// Proposals this pass announced — new ones, plus any that were stored
    /// but still owed their event. Refreshed and already-decided ones are
    /// counted, not returned: they announce nothing.
    pub proposed: Vec<Proposal>,
    /// Why the subject was not searched, when it wasn't.
    pub skipped: Option<Skipped>,
}

impl SignalOutcome {
    /// A pass that never reached the search. Deliberately *not* where the
    /// metric is incremented: a constructor with a telemetry side effect is
    /// invisible two call sites away, and one that fires from a test fixture
    /// is worse. [`LinkSignalConsumer::dispatch`] counts, once, in one place.
    fn skipped(reason: Skipped) -> Self {
        Self {
            proposed: Vec::new(),
            skipped: Some(reason),
        }
    }

    /// The metric label for whatever this pass did — `searched` when it ran.
    fn outcome_label(&self) -> &'static str {
        match self.skipped {
            Some(reason) => reason.label(),
            None => "searched",
        }
    }
}

/// The clustering-signal core: stateless, holding only its seams and bounds,
/// so the consumer below is a thin event→address mapping over it (the
/// [`crate::embedding_job`] split).
#[derive(Clone)]
pub struct LinkSignal {
    chain: Chain,
    seams: LinkSignalSeams,
    /// The one feature space this node compares in — resolved at boot, never
    /// per event.
    schema: &'static BehaviorSchema,
    limits: SimilarityLimits,
    policy: LinkSignalPolicy,
    shutdown: CancellationToken,
    publish_backoff: Duration,
}

impl LinkSignal {
    pub fn new(
        chain: Chain,
        seams: LinkSignalSeams,
        schema: &'static BehaviorSchema,
        limits: SimilarityLimits,
        policy: LinkSignalPolicy,
        shutdown: CancellationToken,
        publish_backoff: Duration,
    ) -> Self {
        Self {
            chain,
            seams,
            schema,
            limits,
            policy,
            shutdown,
            publish_backoff,
        }
    }

    pub fn shutdown(&self) -> &CancellationToken {
        &self.shutdown
    }

    /// The gates that need no store read, in cost order — pure, so all three
    /// are one testable function rather than an if-ladder interleaved with
    /// `await`s. `None` means "this subject is worth a search".
    ///
    /// The ordering is the point: a foreign chain is a field comparison, a
    /// foreign schema is two string compares, and the zero-vector check is a
    /// scan of ~33 floats the event already carries. All three run before the
    /// first round trip, and none of them can be reordered without making the
    /// cheapest check the last one.
    fn store_free_gate(&self, chain: Chain, event: &AddressEmbeddingUpdated) -> Option<Skipped> {
        if chain != self.chain {
            return Some(Skipped::ForeignChain);
        }
        // Both halves of the stamp, not just the version: a vector written
        // under the same version name over an edited schema is a different
        // feature space wearing the right label, which is exactly what the
        // schema hash exists to catch.
        if event.embedding_version != self.schema.version()
            || event.schema_hash != self.schema.content_hash()
        {
            return Some(Skipped::ForeignSchema);
        }
        if event.vector.iter().all(|value| *value == 0.0) {
            return Some(Skipped::NoSignal);
        }
        None
    }

    /// Evaluate one recomputed vector: gate, search, propose, store, announce.
    ///
    /// `at` is explicit rather than an ambient clock — the label-validity read,
    /// the baseline's staleness rule and the proposal's timestamps are all
    /// judged against the same instant, the `as_of` discipline the embedding
    /// kernel established.
    pub async fn evaluate(
        &self,
        chain: Chain,
        event: &AddressEmbeddingUpdated,
        at: DateTime<Utc>,
    ) -> Result<SignalOutcome, LinkSignalError> {
        if let Some(reason) = self.store_free_gate(chain, event) {
            return Ok(SignalOutcome::skipped(reason));
        }

        // Membership from the store, not from the event: the event's
        // `entity_id` is as of the vector's compute time, and a merge since
        // then is exactly the case where re-searching would be wasted work.
        let subject_entity = self
            .seams
            .stores
            .entities
            .entity_for_address(&event.address)
            .await?;
        if self.policy.scope == SearchScope::UnclusteredOnly && subject_entity.is_some() {
            return Ok(SignalOutcome::skipped(Skipped::AlreadyClustered));
        }

        let search = similarity::similar_addresses(SearchRequest {
            store: self.seams.embeddings.as_ref(),
            chain: self.chain,
            address: &event.address,
            schema: self.schema,
            baseline: self.seams.baseline.get(at),
            limits: self.limits,
            requested_results: self.policy.neighbors,
            now: at,
        })
        .await;

        let search = match search {
            Ok(Some(search)) => search,
            // The vector the event announced isn't readable yet (the publish
            // and the ClickHouse write are not one transaction) — a skip, not
            // a failure: the next recomputation carries the same address.
            Ok(None) => return Ok(SignalOutcome::skipped(Skipped::NotEmbedded)),
            // The two *states* a search reports instead of failing. Both are
            // answers about the data, and neither is retryable on this
            // consumer's timescale.
            Err(SimilarityError::NoBaseline { .. }) => {
                return Ok(SignalOutcome::skipped(Skipped::NoBaseline))
            }
            Err(SimilarityError::NoSignal { .. }) => {
                return Ok(SignalOutcome::skipped(Skipped::NoSignal))
            }
            Err(err) => return Err(err.into()),
        };

        if search.results.is_empty() {
            return Ok(SignalOutcome {
                proposed: Vec::new(),
                skipped: None,
            });
        }

        // One batched read each for the two facts the decision needs, over the
        // subject *and* its neighbours together — the page-shaped discipline
        // the embedding job established. The subject rides along because its
        // own labels decide whether a derived label is warranted below.
        let mut addresses: Vec<AccountAddress> =
            search.results.iter().map(|hit| hit.address).collect();
        addresses.push(event.address);
        let mut labels = self
            .seams
            .stores
            .labels
            .labels_for_many(&addresses, at)
            .await?;
        let entities = self
            .seams
            .stores
            .entities
            .entities_for_addresses(&addresses)
            .await?;
        // Whether the subject already carries a flag of its own — directly, or
        // from either flywheel. Handed to `plan`, which owns what follows from
        // it.
        let subject_flagged = labels
            .remove(&event.address)
            .unwrap_or_default()
            .iter()
            .any(|label| FLAGGED_KINDS.contains(&label.kind));

        let proposals = propose(ProposalInputs {
            search: &search,
            subject_entity,
            neighbor_labels: &labels,
            neighbor_entities: &entities,
            policy: self.policy.proposal,
            at,
        });
        for (_, reason) in &proposals.suppressed {
            metrics::counter!(SUPPRESSED_TOTAL, "reason" => <&str>::from(*reason)).increment(1);
        }

        // ── Store, then plan, then apply ─────────────────────────────────
        // The store call is what decides which proposals still owe an
        // announcement, so it necessarily comes first and is the one part that
        // cannot be planned ahead. Everything that *follows* from its answer is
        // a pure function of it.
        let mut owed = Vec::new();
        for proposal in proposals.candidates {
            let outcome = self.seams.links.propose_link(&proposal).await?;
            metrics::counter!(PROPOSALS_TOTAL, "outcome" => <&str>::from(outcome)).increment(1);
            if outcome == ProposalOutcome::ReAnnounce {
                // Visible on purpose: this is the crash window being covered,
                // and it is the only evidence from inside the process that the
                // announcement would otherwise have been lost.
                tracing::info!(
                    candidate_id = %proposal.candidate_id,
                    "re-announcing a stored proposal that never reached the bus",
                );
            }
            if outcome.needs_announcement() {
                owed.push(proposal);
            }
        }

        let effects = plan(&owed, subject_flagged);
        self.apply(&effects, at).await?;

        Ok(SignalOutcome {
            proposed: owed,
            skipped: None,
        })
    }

    /// Drain proposals that were stored but never announced — the backstop
    /// behind [`LinkCandidateStore::unannounced_links`].
    ///
    /// Redelivery covers the ordinary crash, because the offset was never
    /// committed. This covers the cases it cannot: a consumer group reset
    /// forward, a topic compacted past the event, an operator who moved
    /// offsets. Run at boot and on a slow timer; its normal result is zero.
    ///
    /// **Announcements only, deliberately.** It does not re-plan labels. A
    /// missed event is unrecoverable — nothing else will ever publish it — while
    /// a missed label is not: the sweep revisits the address, the normal path
    /// re-derives it, and minting one here without the subject's current label
    /// context would be guessing at a §8.1 claim rather than deriving it.
    pub async fn recover_unannounced(&self, limit: usize) -> Result<usize, LinkSignalError> {
        let owed = self.seams.links.unannounced_links(limit).await?;
        if owed.is_empty() {
            return Ok(0);
        }
        tracing::warn!(
            count = owed.len(),
            "found stored proposals that never reached the bus; announcing them now",
        );
        let effects: Vec<Effect> = owed.into_iter().map(Effect::Announce).collect();
        self.apply(&effects, Utc::now()).await?;
        metrics::counter!(RECOVERED_TOTAL).increment(effects.len() as u64);
        Ok(effects.len())
    }

    /// Perform one planned effect list, in order.
    ///
    /// Ordering within an effect is the part that carries the correctness
    /// argument: an `Announce` publishes **and then** stamps `announced_at`,
    /// never the reverse. A stamp before a successful publish is precisely the
    /// silent loss the column exists to close — it would mark the event as
    /// delivered on the strength of an intention.
    async fn apply(&self, effects: &[Effect], at: DateTime<Utc>) -> Result<(), LinkSignalError> {
        for effect in effects {
            match effect {
                Effect::Announce(proposal) => {
                    tracing::info!(
                        candidate_id = %proposal.candidate_id,
                        subject = %proposal.counterpart(&proposal.anchor).unwrap_or(proposal.anchor),
                        anchor = %proposal.anchor,
                        similarity = %proposal.similarity,
                        confidence = proposal.confidence.get(),
                        "behavioral candidate link proposed (not a merge)",
                    );
                    self.publish(DomainEvent::EntityLinkProposed(link_proposed(proposal)))
                        .await;
                    self.seams
                        .links
                        .mark_announced(proposal.candidate_id, at)
                        .await?;
                }
                Effect::MintLabel(label) => {
                    // `false` is a redelivery landing on the deterministic id —
                    // the label already exists, so there is nothing to evict and
                    // nothing new to announce. This is the step that makes the
                    // label→embedding→signal→label cycle a fixpoint.
                    if self.seams.stores.labels.add_label(label).await? {
                        self.seams.cache.evict(&label.address).await?;
                        self.publish(DomainEvent::LabelAdded(LabelAdded {
                            address: label.address,
                            kind: <&str>::from(label.kind).to_owned(),
                            value: label.value.clone(),
                            confidence: label.confidence,
                            source: <&str>::from(label.source).to_owned(),
                        }))
                        .await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn publish(&self, payload: DomainEvent) {
        publish_resilient(
            self.seams.sink.as_ref(),
            EventEnvelope::new(self.chain, payload),
            self.publish_backoff,
            &self.shutdown,
        )
        .await;
    }
}

/// The proposal → wire mapping. A free function, and pure: the event is a
/// projection of the proposal and nothing else, so it belongs nowhere that has
/// a `self` with seams on it.
///
/// `subject`/`candidate` are the *directional* view the wire wants (who was
/// searched, who they resemble) recovered from the stored unordered pair —
/// `anchor` is the one carried verbatim, because it is the only direction the
/// claim actually has.
fn link_proposed(proposal: &Proposal) -> EntityLinkProposed {
    let subject = proposal
        .counterpart(&proposal.anchor)
        .unwrap_or(proposal.anchor);
    let entity_of = |address: AccountAddress| {
        if address == proposal.address_a {
            proposal.entity_a
        } else {
            proposal.entity_b
        }
    };
    EntityLinkProposed {
        candidate_id: proposal.candidate_id,
        subject,
        subject_entity: entity_of(subject),
        candidate: proposal.anchor,
        candidate_entity: entity_of(proposal.anchor),
        anchor: proposal.anchor,
        anchor_labels: proposal
            .anchor_labels
            .iter()
            .map(|kind| <&str>::from(*kind).to_owned())
            .collect(),
        similarity: proposal.similarity.get(),
        confidence: proposal.confidence,
        embedding_version: proposal.embedding_version.clone(),
        schema_hash: proposal.schema_hash.clone(),
        factors: proposal
            .factors
            .iter()
            .map(|factor| LinkFactor {
                feature: factor.feature.clone(),
                subject_value: factor.subject_value,
                candidate_value: factor.candidate_value,
                contribution: factor.contribution,
            })
            .collect(),
    }
}

/// The Kafka consumer: a thin event→[`LinkSignal::evaluate`] mapping.
#[derive(Clone)]
pub struct LinkSignalConsumer {
    signal: LinkSignal,
}

impl LinkSignalConsumer {
    pub fn new(signal: LinkSignal) -> Self {
        Self { signal }
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
            "link_signal",
            retry_backoff,
            dlq,
            self,
            shutdown,
        )
        .await
    }

    async fn dispatch(&self, envelope: EventEnvelope) -> Handled {
        let chain = envelope.chain;
        let at = envelope.occurred_at;
        let DomainEvent::AddressEmbeddingUpdated(event) = envelope.payload else {
            tracing::warn!(
                event = envelope.payload.event_type(),
                "unexpected event on the link-signal topic; skipping"
            );
            return Handled::Commit;
        };
        match self.signal.evaluate(chain, &event, at).await {
            Ok(outcome) => {
                // The one place a subject is counted: `evaluate` returns what
                // happened, `dispatch` records it. Keeping this out of the
                // constructors means a fixture that builds a `SignalOutcome`
                // cannot move a production counter.
                metrics::counter!(SUBJECTS_TOTAL, "outcome" => outcome.outcome_label())
                    .increment(1);
                if self.signal.shutdown().is_cancelled() {
                    Handled::Stop
                } else {
                    Handled::Commit
                }
            }
            Err(err) => event_bus::handled(err, "link_signal"),
        }
    }
}

#[async_trait]
impl EventHandler for LinkSignalConsumer {
    async fn handle(&self, envelope: EventEnvelope) -> Handled {
        self.dispatch(envelope).await
    }
}

/// Everything a test needs to drive the signal against in-memory doubles —
/// built once here rather than in each test, so a seam added later shows up as
/// one compile error instead of a dozen.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedding::BehaviorVector;
    use crate::embedding::{self, baseline};
    use crate::model::{LabelRecord, LabelSource};
    use crate::store::{EntityStore, LabelStore};
    use crate::test_util::{
        store_seams, InMemoryHotCache, InMemoryIntelligenceStore, InMemoryLinkCandidateStore,
        RecordingEmbeddingStore,
    };
    use event_bus::test_util::RecordingSink;
    use events::primitives::LabelKind;

    fn addr(byte: u8) -> AccountAddress {
        AccountAddress::repeat_byte(byte)
    }

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
    }

    /// A vector that is *not* the population median on every feature, so it has
    /// a direction to search along. `seed` shifts it so two harness addresses
    /// can be made near-identical or unrelated at will.
    fn vector(schema: &BehaviorSchema, seed: f32) -> Vec<f32> {
        (0..schema.features().len())
            .map(|i| seed + i as f32 * 0.01)
            .collect()
    }

    struct Harness {
        signal: LinkSignal,
        store: Arc<InMemoryIntelligenceStore>,
        links: Arc<InMemoryLinkCandidateStore>,
        sink: Arc<RecordingSink>,
        schema: &'static BehaviorSchema,
    }

    impl Harness {
        fn new(policy: LinkSignalPolicy) -> Self {
            let schema = embedding::default_embedder().schema();
            let store = Arc::new(InMemoryIntelligenceStore::new());
            let links = Arc::new(InMemoryLinkCandidateStore::new());
            let embeddings = Arc::new(RecordingEmbeddingStore::new());
            let sink = Arc::new(RecordingSink::default());
            let baseline = Arc::new(BaselineSnapshot::new(
                Chain(1),
                schema.version().to_owned(),
                crate::baseline_cache::BaselineCacheConfig::default(),
            ));
            let signal = LinkSignal::new(
                Chain(1),
                LinkSignalSeams {
                    stores: store_seams(&store),
                    links: links.clone(),
                    embeddings: embeddings.clone(),
                    cache: Arc::new(InMemoryHotCache::new()),
                    sink: sink.clone(),
                    baseline,
                },
                schema,
                SimilarityLimits::default(),
                policy,
                CancellationToken::new(),
                Duration::from_millis(1),
            );
            Self {
                signal,
                store,
                links,
                sink,
                schema,
            }
        }
    }

    #[test]
    fn the_consumer_reads_only_the_embedding_stream() {
        assert_eq!(CONSUMED_EVENT_TYPES, &["AddressEmbeddingUpdated"]);
        // Panics if the name has drifted from the schema.
        assert_eq!(consumed_topics().len(), 1);
    }

    #[tokio::test]
    async fn a_foreign_chain_or_schema_is_skipped_before_any_store_read() {
        let h = Harness::new(LinkSignalPolicy::default());
        let event = AddressEmbeddingUpdated {
            address: addr(1),
            entity_id: None,
            embedding_version: h.schema.version().to_owned(),
            schema_hash: h.schema.content_hash().to_owned(),
            vector: vector(h.schema, 1.0),
            top_factors: Vec::new(),
            observations_truncated: false,
        };

        let out = h.signal.evaluate(Chain(8453), &event, at()).await.unwrap();
        assert_eq!(out.skipped, Some(Skipped::ForeignChain));

        let mut foreign = event.clone();
        foreign.schema_hash = "not-our-schema".into();
        let out = h.signal.evaluate(Chain(1), &foreign, at()).await.unwrap();
        assert_eq!(out.skipped, Some(Skipped::ForeignSchema));

        let mut other_version = event.clone();
        other_version.embedding_version = "behavior-v99".into();
        let out = h
            .signal
            .evaluate(Chain(1), &other_version, at())
            .await
            .unwrap();
        assert_eq!(out.skipped, Some(Skipped::ForeignSchema));

        let mut flat = event;
        flat.vector = vec![0.0; h.schema.features().len()];
        let out = h.signal.evaluate(Chain(1), &flat, at()).await.unwrap();
        assert_eq!(out.skipped, Some(Skipped::NoSignal));

        assert!(h.sink.events().is_empty(), "no gate publishes anything");
    }

    #[tokio::test]
    async fn an_already_clustered_subject_is_skipped_unless_the_operator_asks() {
        let h = Harness::new(LinkSignalPolicy::default());
        let entity = events::primitives::EntityId::new();
        h.store
            .create_entity(entity, &addr(1), "test", at())
            .await
            .unwrap();
        let event = AddressEmbeddingUpdated {
            address: addr(1),
            entity_id: None,
            embedding_version: h.schema.version().to_owned(),
            schema_hash: h.schema.content_hash().to_owned(),
            vector: vector(h.schema, 1.0),
            top_factors: Vec::new(),
            observations_truncated: false,
        };
        let out = h.signal.evaluate(Chain(1), &event, at()).await.unwrap();
        assert_eq!(out.skipped, Some(Skipped::AlreadyClustered));

        // The same subject, with the gate off, gets as far as the search.
        let open = Harness::new(LinkSignalPolicy {
            scope: SearchScope::All,
            ..LinkSignalPolicy::default()
        });
        open.store
            .create_entity(entity, &addr(1), "test", at())
            .await
            .unwrap();
        let out = open.signal.evaluate(Chain(1), &event, at()).await.unwrap();
        assert_ne!(out.skipped, Some(Skipped::AlreadyClustered));
    }

    /// The whole pass, end to end: a fresh address that behaves like a
    /// known scammer earns a proposal, an `EntityLinkProposed`, and a
    /// reduced-confidence `ScammerAssociate` — and no merge.
    #[tokio::test]
    async fn a_match_to_a_known_scammer_proposes_a_link_and_a_reduced_confidence_label() {
        let h = Harness::new(LinkSignalPolicy::default());
        let schema = h.schema;
        let (subject, anchor) = (addr(1), addr(2));

        // Two near-identical vectors, and a population baseline wide enough to
        // standardize against.
        let subject_vector = vector(schema, 1.0);
        let anchor_vector: Vec<f32> = subject_vector.iter().map(|v| v * 1.01).collect();
        h.seed_embeddings(&[(subject, subject_vector.clone()), (anchor, anchor_vector)])
            .await;
        h.seed_baseline(&subject_vector).await;

        h.store
            .add_label(&LabelRecord::new(
                anchor,
                LabelKind::KnownScammer,
                "ofac",
                LabelSource::ExternalFeed,
                "ofac_sdn",
                at(),
            ))
            .await
            .unwrap();

        let out = h
            .signal
            .evaluate(Chain(1), &h.event(subject, &subject_vector), at())
            .await
            .unwrap();

        assert_eq!(out.proposed.len(), 1, "one proposal");
        let candidate = &out.proposed[0];
        assert_eq!(candidate.anchor, anchor);

        let kinds: Vec<&str> = h.sink.events().iter().map(|e| e.event_type()).collect();
        assert!(kinds.contains(&"EntityLinkProposed"));
        assert!(kinds.contains(&"LabelAdded"));
        assert!(
            !kinds.contains(&"EntityMerged") && !kinds.contains(&"EntityCreated"),
            "a behavioral match must never move the entity graph"
        );

        let labels = h.store.labels_for(&subject, at()).await.unwrap();
        let derived = labels
            .iter()
            .find(|l| l.kind == LabelKind::ScammerAssociate)
            .expect("a ScammerAssociate on the subject");
        assert!(
            derived.confidence.get() < LabelSource::EntityDerived.default_confidence().get(),
            "the behavioral band is below the clustering one"
        );
    }

    /// The flywheel's cycle is a fixpoint: the second delivery of the same
    /// recomputation writes nothing new and announces nothing.
    #[tokio::test]
    async fn a_redelivered_recomputation_announces_nothing_the_second_time() {
        let h = Harness::new(LinkSignalPolicy::default());
        let (subject, anchor) = (addr(1), addr(2));
        let subject_vector = vector(h.schema, 1.0);
        let anchor_vector: Vec<f32> = subject_vector.iter().map(|v| v * 1.01).collect();
        h.seed_embeddings(&[(subject, subject_vector.clone()), (anchor, anchor_vector)])
            .await;
        h.seed_baseline(&subject_vector).await;
        h.store
            .add_label(&LabelRecord::new(
                anchor,
                LabelKind::KnownScammer,
                "ofac",
                LabelSource::ExternalFeed,
                "ofac_sdn",
                at(),
            ))
            .await
            .unwrap();

        let event = h.event(subject, &subject_vector);
        let first = h.signal.evaluate(Chain(1), &event, at()).await.unwrap();
        assert_eq!(first.proposed.len(), 1);
        let published = h.sink.events().len();

        let second = h.signal.evaluate(Chain(1), &event, at()).await.unwrap();
        assert!(
            second.proposed.is_empty(),
            "a refreshed proposal is not a new one"
        );
        assert_eq!(
            h.sink.events().len(),
            published,
            "nothing is republished on redelivery"
        );
        assert_eq!(h.links.len(), 1, "one row, not two");
    }

    /// The bug the `announced_at` column exists to close, end to end.
    ///
    /// A crash between the Postgres commit and the Kafka publish leaves a row
    /// with no event. The consumer offset was never committed, so the event
    /// redelivers — and an "announce only what I just inserted" rule would see
    /// an existing row, stay silent, and lose the announcement **permanently**.
    /// Here the redelivery re-announces instead.
    #[tokio::test]
    async fn a_proposal_that_never_reached_the_bus_is_re_announced_on_redelivery() {
        let h = Harness::new(LinkSignalPolicy::default());
        let (subject, anchor) = (addr(1), addr(2));
        let subject_vector = vector(h.schema, 1.0);
        let anchor_vector: Vec<f32> = subject_vector.iter().map(|v| v * 1.01).collect();
        h.seed_embeddings(&[(subject, subject_vector.clone()), (anchor, anchor_vector)])
            .await;
        h.seed_baseline(&subject_vector).await;
        h.store
            .add_label(&LabelRecord::new(
                anchor,
                LabelKind::KnownScammer,
                "ofac",
                LabelSource::ExternalFeed,
                "ofac_sdn",
                at(),
            ))
            .await
            .unwrap();

        let event = h.event(subject, &subject_vector);
        let first = h.signal.evaluate(Chain(1), &event, at()).await.unwrap();
        assert_eq!(first.proposed.len(), 1);
        let announced = h
            .sink
            .count(|e| matches!(e, DomainEvent::EntityLinkProposed(_)));
        assert_eq!(announced, 1);

        // The crash: the row is committed, the publish never happened.
        h.links.forget_announcements();
        h.sink.clear();

        let redelivered = h.signal.evaluate(Chain(1), &event, at()).await.unwrap();
        assert_eq!(
            redelivered.proposed.len(),
            1,
            "an unannounced row still owes its event"
        );
        assert_eq!(
            h.sink
                .count(|e| matches!(e, DomainEvent::EntityLinkProposed(_))),
            1,
            "and the redelivery publishes it rather than silently dropping it"
        );
        assert_eq!(
            h.links.len(),
            1,
            "still one row — the re-announce is not a new proposal"
        );

        // Once announced, the *next* redelivery is silent again: at-least-once,
        // not every-time.
        h.sink.clear();
        let third = h.signal.evaluate(Chain(1), &event, at()).await.unwrap();
        assert!(third.proposed.is_empty());
        assert!(h.sink.is_empty());
    }

    /// The rule the effects layer made assertable, checked through the real
    /// consumer: three anchors, three proposals, **one** label.
    #[tokio::test]
    async fn many_scammer_anchors_earn_one_label_not_one_each() {
        let h = Harness::new(LinkSignalPolicy::default());
        let subject = addr(1);
        let subject_vector = vector(h.schema, 1.0);

        let mut rows = vec![(subject, subject_vector.clone())];
        for (i, anchor) in [addr(2), addr(3), addr(4)].into_iter().enumerate() {
            let scaled: Vec<f32> = subject_vector
                .iter()
                .map(|v| v * (1.01 + i as f32 * 0.001))
                .collect();
            rows.push((anchor, scaled));
            h.store
                .add_label(&LabelRecord::new(
                    anchor,
                    LabelKind::KnownScammer,
                    "ofac",
                    LabelSource::ExternalFeed,
                    "ofac_sdn",
                    at(),
                ))
                .await
                .unwrap();
        }
        h.seed_embeddings(&rows).await;
        h.seed_baseline(&subject_vector).await;

        let out = h
            .signal
            .evaluate(Chain(1), &h.event(subject, &subject_vector), at())
            .await
            .unwrap();

        assert_eq!(out.proposed.len(), 3, "every anchor is proposed");
        assert_eq!(
            h.sink
                .count(|e| matches!(e, DomainEvent::EntityLinkProposed(_))),
            3
        );
        assert_eq!(
            h.sink.count(|e| matches!(e, DomainEvent::LabelAdded(_))),
            1,
            "one ScammerAssociate, not three — the subject is flagged after the first"
        );
        let labels = h.store.labels_for(&subject, at()).await.unwrap();
        assert_eq!(
            labels
                .iter()
                .filter(|l| l.kind == LabelKind::ScammerAssociate)
                .count(),
            1
        );
    }

    impl Harness {
        fn event(&self, address: AccountAddress, values: &[f32]) -> AddressEmbeddingUpdated {
            AddressEmbeddingUpdated {
                address,
                entity_id: None,
                embedding_version: self.schema.version().to_owned(),
                schema_hash: self.schema.content_hash().to_owned(),
                vector: values.to_vec(),
                top_factors: Vec::new(),
                observations_truncated: false,
            }
        }

        async fn seed_embeddings(&self, rows: &[(AccountAddress, Vec<f32>)]) {
            let vectors: Vec<BehaviorVector> = rows
                .iter()
                .map(|(address, values)| BehaviorVector {
                    address: *address,
                    entity_id: None,
                    schema: self.schema,
                    values: values.clone(),
                    observations_truncated: false,
                    computed_at: at(),
                })
                .collect();
            self.signal
                .seams
                .embeddings
                .append(Chain(1), &vectors)
                .await
                .expect("seeding embeddings");
        }

        /// A baseline wide enough that `standardize` accepts it — built from a
        /// spread of perturbations of one vector so every feature has non-zero
        /// MAD.
        async fn seed_baseline(&self, around: &[f32]) {
            let sample: Vec<Vec<f32>> = (0..baseline::MIN_SAMPLES + 1)
                .map(|i| around.iter().map(|v| v * (1.0 + i as f32 * 0.05)).collect())
                .collect();
            let computed =
                baseline::compute(self.schema, &sample, at()).expect("a baseline over the sample");
            self.signal
                .seams
                .embeddings
                .put_baseline(Chain(1), &computed)
                .await
                .expect("storing the baseline");
            self.signal
                .seams
                .baseline
                .refresh(self.signal.seams.embeddings.as_ref(), at())
                .await
                .expect("loading the baseline snapshot");
        }
    }
}
