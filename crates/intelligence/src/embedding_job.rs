//! The behavior-embedding **compute core** (§20.3, Sprint 19 t1) — the I/O
//! shell around [`crate::embedding`]'s pure kernel.
//!
//! [`BehaviorEmbedder::embed`] is the decision; [`Embedder`] is everything
//! around it: reading an address's observations from the ClickHouse adjacency
//! store and its labels/entity/attributions from the Postgres system of
//! record, deciding whether the result is worth writing, appending it, and
//! publishing `AddressEmbeddingUpdated`.
//!
//! Two things drive it, and they live in their own modules because they are
//! different jobs sharing one core:
//! [`crate::embedding_sweep`] (the schedule) and
//! [`crate::embedding_consumer`] (the invalidation stream).
//!
//! ## Everything here is page-shaped, on purpose
//!
//! The naive form of this job is "for each address, load its inputs" — seven
//! sequential round trips per address, which at a sweep page of 500 is 3,500
//! queries to embed 500 addresses. [`load_behavior_inputs_many`] instead
//! issues a **fixed number of queries per page** (one ClickHouse history read,
//! one batched label read covering subjects *and* their counterparties, and
//! four batched Postgres reads) regardless of how many addresses the page
//! holds. The single-address entry point is a thin wrapper over the batched
//! one, so the two cannot drift on what they read.
//!
//! This is the difference between a job that works on a demo graph and one
//! that works on mainnet, and it is why [`crate::adjacency::AdjacencyStore`]
//! grew `edge_history_many` and the store seams grew their `*_many` siblings.
//!
//! ## Not every recomputation is worth writing down
//!
//! A dormant address recomputed an hour later differs from its predecessor in
//! exactly one way: it is an hour older. Publishing that forever is noise on
//! the bus and rows in the event store no consumer can act on, and appending
//! it forever grows the table as address-space x time. [`decide_write`] is the
//! pure rule: write when the vector is new, when its *content* moved, when the
//! schema behind it changed, or when the stored one is older than
//! [`EmbeddingLimits::refresh_interval`] — otherwise skip and count it.
//!
//! The refresh floor is what keeps `computed_at` meaningful: without it a
//! stored vector's timestamp would say when the behavior last *changed*, with
//! no way to tell that from "the job stopped running six weeks ago".
//!
//! ## Idempotency and ordering (§4/§18)
//!
//! [`BehaviorEmbedder::embed`] is a pure function of current store state and
//! the `as_of` instant, never of a triggering event's payload — so a
//! redelivered event recomputes to the same vector, and two events landing out
//! of order still converge on current truth. There is nothing to deduplicate.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use event_bus::{publish_resilient, EventSink, Transience};
use events::primitives::{AccountAddress, Chain, EntityId};
use events::{DomainEvent, EventEnvelope};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::adjacency::{AdjacencyStore, GraphError};
use crate::embedding::{default_embedder, BehaviorEmbedder, BehaviorInputs, BehaviorVector};
use crate::embedding_store::{EmbeddingStore, EmbeddingStoreError, StoredEmbedding};
use crate::model::LabelKind;
use crate::store::{StoreError, StoreSeams};

// ── Metrics (§19) ────────────────────────────────────────────────────────────
// No-ops until the binary installs an exporter (`telemetry::metrics::init`) —
// the same stance as this crate's other counters.

/// Vectors computed, labelled by what triggered the computation.
pub const EMBEDDINGS_COMPUTED_TOTAL: &str = "intelligence_embeddings_computed_total";
/// Vectors actually written, labelled by *why* they were worth writing —
/// `new`, `changed`, `schema_changed` or `refresh`. A healthy steady state is
/// mostly `changed` and `refresh`; a flood of `schema_changed` means a version
/// rollout is in flight.
pub const EMBEDDINGS_WRITTEN_TOTAL: &str = "intelligence_embeddings_written_total";
/// Recomputations that produced an unchanged vector and were skipped. The
/// ratio against `..._computed_total` is how much the sweep is *saving*; a
/// collapse toward zero means change detection has stopped paying and the
/// refresh interval or the sweep cadence wants revisiting.
pub const EMBEDDINGS_SKIPPED_TOTAL: &str = "intelligence_embeddings_skipped_total";
/// Vectors computed over a *truncated* observation history — a hub whose
/// cadence features describe a recent window rather than its whole life. A
/// rising share means the history cap is biting more of the graph.
pub const EMBEDDINGS_TRUNCATED_TOTAL: &str = "intelligence_embeddings_truncated_total";
/// Wall time to load, embed, store and publish one whole page.
pub const EMBEDDING_PAGE_DURATION: &str = "intelligence_embedding_page_duration_seconds";

/// Operator-tunable bounds for the compute core. Every one is a *bound*, not a
/// preference: each caps something the graph would otherwise make unbounded.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddingLimits {
    /// Most-recent observations read per address (§8.2's hub rule at edge
    /// granularity). A hub's vector describes this window, and says so through
    /// [`BehaviorVector::observations_truncated`].
    pub history_cap: u32,
    /// Addresses per batched load. Bounds the size of one `IN (...)` list and
    /// one page's memory; it does **not** bound total work, which is the
    /// caller's budget.
    pub batch_size: usize,
    /// How many pages may be in flight at once, process-wide — see
    /// [`Embedder::new`].
    pub page_concurrency: usize,
    /// How stale a stored vector may get before it is rewritten even though
    /// nothing about it changed. Keeps `computed_at` readable as "last
    /// verified" rather than "last changed".
    pub refresh_interval: Duration,
}

impl Default for EmbeddingLimits {
    fn default() -> Self {
        Self {
            history_cap: 512,
            batch_size: 500,
            page_concurrency: 4,
            refresh_interval: Duration::from_secs(24 * 3_600),
        }
    }
}

/// A failure computing embeddings. Wraps the three seams and forwards the
/// shared retry/skip decision (§4): a transient fault leaves the Kafka offset
/// for redelivery (recompute is naturally idempotent, so a retry converges); a
/// permanent one is logged and skipped so one poison event can't wedge the
/// stream.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddingError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Graph(#[from] GraphError),
    #[error(transparent)]
    EmbeddingStore(#[from] EmbeddingStoreError),
    /// A concurrent page task panicked instead of returning — never retried (a
    /// panic is a bug in the compute path, not a blip a redelivery could fix).
    #[error("a concurrent embedding task did not complete: {0}")]
    Task(#[from] tokio::task::JoinError),
}

impl Transience for EmbeddingError {
    /// Whether retrying the same work could plausibly succeed.
    fn is_transient(&self) -> bool {
        match self {
            EmbeddingError::Store(err) => err.is_transient(),
            EmbeddingError::Graph(err) => err.is_transient(),
            EmbeddingError::EmbeddingStore(err) => err.is_transient(),
            EmbeddingError::Task(_) => false,
        }
    }
}

/// What caused a recompute — a metric label, and a `&'static str` rather than
/// a `String` because the label set must stay bounded (a per-address or
/// per-event-type label would be a cardinality explosion in Prometheus).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The scheduled sweep.
    Sweep,
    /// An invalidating domain event.
    Event,
    /// A one-shot operator command.
    Manual,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Trigger::Sweep => "sweep",
            Trigger::Event => "event",
            Trigger::Manual => "manual",
        }
    }
}

/// Why a freshly computed vector is (or isn't) worth storing.
///
/// A closed enum rather than a bool so the *reason* reaches the metric label
/// and the logs: "we wrote 40,000 vectors" is not actionable, "we wrote 40,000
/// vectors because a schema rollout is in flight" is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteDecision {
    /// This address has never been embedded under this version.
    New,
    /// The vector's content moved.
    Changed,
    /// Same version name, different schema hash — a frozen schema was edited
    /// under a version that didn't move. Always rewritten: the stored vector
    /// is in a different feature space than the current one, so leaving it
    /// would let a comparison silently mix the two.
    SchemaChanged,
    /// Nothing moved, but the stored vector is older than the refresh floor.
    Refresh,
    /// Nothing moved and the stored vector is recent enough.
    Skip,
}

impl WriteDecision {
    /// Whether this decision results in a store write and a published event.
    pub fn writes(self) -> bool {
        !matches!(self, WriteDecision::Skip)
    }

    /// The bounded metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            WriteDecision::New => "new",
            WriteDecision::Changed => "changed",
            WriteDecision::SchemaChanged => "schema_changed",
            WriteDecision::Refresh => "refresh",
            WriteDecision::Skip => "skip",
        }
    }
}

/// Decide whether a freshly computed vector is worth writing, given whatever
/// is already stored. Pure — the same inputs always yield the same decision,
/// so a redelivered event converges rather than re-litigating it.
///
/// `now` is the instant the *freshness* of `previous` is judged against, taken
/// explicitly rather than from an ambient clock so replay is deterministic
/// (§18) and the refresh floor is testable without sleeping.
pub fn decide_write(
    previous: Option<&StoredEmbedding>,
    vector: &BehaviorVector,
    refresh_interval: Duration,
    now: DateTime<Utc>,
) -> WriteDecision {
    let Some(previous) = previous else {
        return WriteDecision::New;
    };
    if previous.schema_hash != vector.schema_hash() {
        return WriteDecision::SchemaChanged;
    }
    if previous.content_digest() != vector.content_digest() {
        return WriteDecision::Changed;
    }
    let age = now.signed_duration_since(previous.computed_at);
    // A negative age (a stored vector stamped ahead of `now` — clock skew, or
    // a replay running behind live) is *not* stale: treating it as such would
    // rewrite the row on every pass.
    match age.to_std() {
        Ok(age) if age >= refresh_interval => WriteDecision::Refresh,
        _ => WriteDecision::Skip,
    }
}

/// What one call to [`Embedder::compute`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ComputeReport {
    /// Vectors computed (addresses x enabled versions).
    pub computed: usize,
    /// Of those, how many were written and published.
    pub written: usize,
    /// Of those, how many were unchanged and skipped.
    pub skipped: usize,
}

impl ComputeReport {
    fn merge(&mut self, other: ComputeReport) {
        self.computed += other.computed;
        self.written += other.written;
        self.skipped += other.skipped;
    }
}

/// Fetch every input the kernel needs for a whole **page** of addresses, in a
/// fixed number of round trips — see this module's docs on why that matters.
///
/// One ClickHouse history read; one batched label read covering the subjects
/// *and* every counterparty they touched (their labels are the
/// counterparty-type family); one batched sanctions read; and three batched
/// entity/attribution reads. Seven queries for a page of any size, against
/// seven queries **per address** for the naive shape.
pub async fn load_behavior_inputs_many(
    stores: &StoreSeams,
    graph: &dyn AdjacencyStore,
    chain: Chain,
    addresses: &[AccountAddress],
    as_of: DateTime<Utc>,
    history_cap: u32,
) -> Result<HashMap<AccountAddress, (Option<EntityId>, BehaviorInputs)>, EmbeddingError> {
    if addresses.is_empty() {
        return Ok(HashMap::new());
    }

    let histories = graph
        .edge_history_many(chain, addresses, history_cap)
        .await?;

    // Subjects and counterparties in one label read: a subject's own labels
    // and its counterparties' labels are different feature families, but they
    // come from the same table and there is no reason to ask twice.
    let mut label_targets: BTreeSet<AccountAddress> = addresses.iter().copied().collect();
    for history in histories.values() {
        label_targets.extend(history.edges.iter().map(|edge| edge.counterparty));
    }
    let label_targets: Vec<AccountAddress> = label_targets.into_iter().collect();
    let labels = stores.labels.labels_for_many(&label_targets, as_of).await?;

    let sanctions = stores.sanctions.sanction_matches_many(addresses).await?;
    let entity_ids = stores.entities.entities_for_addresses(addresses).await?;

    // A page of 500 addresses often maps to far fewer entities, so dedupe
    // before asking — the batched entity read is over entities, not addresses.
    // Sorted by uuid so the batched query's parameter list is stable for a
    // given page — one less thing that differs between two runs of the same
    // work. (`EntityId` is deliberately not `Ord`; its inner `Uuid` is.)
    let mut unique_entities: Vec<EntityId> = entity_ids
        .values()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    unique_entities.sort_by_key(|id| id.0);
    let entities = stores.entities.entities(&unique_entities).await?;
    let attributions = stores
        .attributions
        .attributions_for_entities(&unique_entities)
        .await?;

    let mut out = HashMap::with_capacity(addresses.len());
    for address in addresses {
        let history = histories.get(address).cloned().unwrap_or_default();

        // The subject is excluded from its own counterparty set: its labels
        // are a separate feature family, and counting itself as its own
        // counterparty would skew the distribution of any address with a
        // self-referencing observation.
        let counterparty_labels = history
            .edges
            .iter()
            .map(|edge| edge.counterparty)
            .filter(|counterparty| counterparty != address)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter_map(|counterparty| {
                let kinds: Vec<LabelKind> = labels
                    .get(&counterparty)
                    .map(|records| records.iter().map(|label| label.kind).collect())
                    .unwrap_or_default();
                (!kinds.is_empty()).then_some((counterparty, kinds))
            })
            .collect();

        let entity_id = entity_ids.get(address).copied();
        out.insert(
            *address,
            (
                entity_id,
                BehaviorInputs {
                    history,
                    counterparty_labels,
                    labels: labels.get(address).cloned().unwrap_or_default(),
                    sanctions: sanctions.get(address).cloned().unwrap_or_default(),
                    attributions: entity_id
                        .and_then(|id| attributions.get(&id).cloned())
                        .unwrap_or_default(),
                    entity: entity_id.and_then(|id| entities.get(&id).cloned()),
                },
            ),
        );
    }
    Ok(out)
}

/// Fetch one address's inputs — a thin wrapper over
/// [`load_behavior_inputs_many`] so the single-address path (the
/// `intelligence embed` CLI) and the page path can never disagree about what
/// the kernel is fed.
pub async fn load_behavior_inputs(
    stores: &StoreSeams,
    graph: &dyn AdjacencyStore,
    chain: Chain,
    address: &AccountAddress,
    as_of: DateTime<Utc>,
    history_cap: u32,
) -> Result<(Option<EntityId>, BehaviorInputs), EmbeddingError> {
    let mut loaded = load_behavior_inputs_many(
        stores,
        graph,
        chain,
        std::slice::from_ref(address),
        as_of,
        history_cap,
    )
    .await?;
    Ok(loaded.remove(address).unwrap_or_default())
}

/// The four seams the compute core needs, bundled so its constructor doesn't
/// take an unreadable wall of `Arc<dyn Trait>` parameters — the same shape
/// [`StoreSeams`] and `cluster::ClusterSeams` already use in this crate.
#[derive(Clone)]
pub struct EmbedderSeams {
    /// Labels, entities, attributions, sanctions — the system of record.
    pub stores: StoreSeams,
    /// The append-only address graph the observations come from.
    pub graph: Arc<dyn AdjacencyStore>,
    /// Where computed vectors are stored and read back for change detection.
    pub embeddings: Arc<dyn EmbeddingStore>,
    /// Where `AddressEmbeddingUpdated` is published.
    pub sink: Arc<dyn EventSink>,
}

/// The behavior-embedding compute core: the graph it reads observations from,
/// the store seams it reads identity from, the append-only vector store it
/// writes to, and the sink it publishes `AddressEmbeddingUpdated` to.
///
/// `Clone` is cheap (every field is `Arc`- or `Copy`-backed), and cloning
/// **shares** the page-concurrency permits — see [`Self::new`].
#[derive(Clone)]
pub struct Embedder {
    chain: Chain,
    stores: StoreSeams,
    graph: Arc<dyn AdjacencyStore>,
    embeddings: Arc<dyn EmbeddingStore>,
    sink: Arc<dyn EventSink>,
    shutdown: CancellationToken,
    limits: EmbeddingLimits,
    /// The schema versions this instance computes, in roster order. More than
    /// one during a version rollout (v1 and v2 stored side by side); exactly
    /// one the rest of the time.
    versions: Vec<&'static dyn BehaviorEmbedder>,
    permits: Arc<Semaphore>,
    publish_backoff: Duration,
}

impl Embedder {
    /// Build the core over its seams. `chain` is the one chain whose adjacency
    /// graph this instance embeds: observations are chain-scoped even though
    /// labels and entities are not, so a deployment covering two chains runs
    /// two instances rather than one that guesses (§13's per-chain stance).
    ///
    /// The page-concurrency [`Semaphore`] is built **here, once**, and shared
    /// by every clone. That is the point: the sweep and the invalidation
    /// consumer both hold clones of this struct and both issue pages against
    /// the *same* Postgres pool, so a per-call bound would silently allow
    /// twice the configured concurrency whenever both are busy.
    pub fn new(
        chain: Chain,
        seams: EmbedderSeams,
        shutdown: CancellationToken,
        limits: EmbeddingLimits,
        versions: Vec<&'static dyn BehaviorEmbedder>,
    ) -> Self {
        let versions = if versions.is_empty() {
            vec![default_embedder()]
        } else {
            versions
        };
        Self {
            chain,
            stores: seams.stores,
            graph: seams.graph,
            embeddings: seams.embeddings,
            sink: seams.sink,
            shutdown,
            limits,
            versions,
            permits: Arc::new(Semaphore::new(limits.page_concurrency.max(1))),
            publish_backoff: event_bus::PUBLISH_BACKOFF,
        }
    }

    /// The chain this instance embeds.
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// The bounds it runs under.
    pub fn limits(&self) -> EmbeddingLimits {
        self.limits
    }

    /// The versions it computes, in roster order.
    pub fn versions(&self) -> &[&'static dyn BehaviorEmbedder] {
        &self.versions
    }

    /// Compute (and, where worthwhile, store and publish) vectors for every
    /// address in `addresses`, deduplicated.
    ///
    /// Work is split into pages of [`EmbeddingLimits::batch_size`] and run
    /// with at most [`EmbeddingLimits::page_concurrency`] pages in flight
    /// process-wide. Every page runs to completion; the *first* error is
    /// returned, so a partial failure is reported rather than silently
    /// dropped.
    pub async fn compute(
        &self,
        addresses: &[AccountAddress],
        as_of: DateTime<Utc>,
        trigger: Trigger,
    ) -> Result<ComputeReport, EmbeddingError> {
        let unique: Vec<AccountAddress> = addresses
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if unique.is_empty() {
            return Ok(ComputeReport::default());
        }

        let mut tasks = JoinSet::new();
        for page in unique.chunks(self.limits.batch_size.max(1)) {
            let permit = self
                .permits
                .clone()
                .acquire_owned()
                .await
                .expect("semaphore is never closed while its owning task is alive");
            let embedder = self.clone();
            let page = page.to_vec();
            tasks.spawn(async move {
                let _permit = permit;
                embedder.compute_page(&page, as_of, trigger).await
            });
        }

        let mut report = ComputeReport::default();
        let mut first_err = None;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(page)) => report.merge(page),
                Ok(Err(err)) => {
                    first_err.get_or_insert(err);
                }
                Err(join_err) => {
                    first_err.get_or_insert(join_err.into());
                }
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(report),
        }
    }

    /// One address, computed and returned — the `intelligence embed` CLI's
    /// entry point, and the readable path in tests. Goes through the same page
    /// machinery, so it exercises exactly what production runs.
    pub async fn compute_one(
        &self,
        address: AccountAddress,
        as_of: DateTime<Utc>,
        trigger: Trigger,
    ) -> Result<Vec<BehaviorVector>, EmbeddingError> {
        let (entity_id, inputs) = load_behavior_inputs(
            &self.stores,
            self.graph.as_ref(),
            self.chain,
            &address,
            as_of,
            self.limits.history_cap,
        )
        .await?;
        let vectors = self.embed_all(address, entity_id, &inputs, as_of);
        self.persist(&vectors, as_of, trigger).await?;
        Ok(vectors)
    }

    /// Every enabled version's vector for one address's inputs.
    fn embed_all(
        &self,
        address: AccountAddress,
        entity_id: Option<EntityId>,
        inputs: &BehaviorInputs,
        as_of: DateTime<Utc>,
    ) -> Vec<BehaviorVector> {
        self.versions
            .iter()
            .map(|embedder| embedder.embed(address, entity_id, inputs, as_of))
            .collect()
    }

    /// Load, embed, decide, store and publish one page.
    async fn compute_page(
        &self,
        addresses: &[AccountAddress],
        as_of: DateTime<Utc>,
        trigger: Trigger,
    ) -> Result<ComputeReport, EmbeddingError> {
        let started = std::time::Instant::now();

        let loaded = load_behavior_inputs_many(
            &self.stores,
            self.graph.as_ref(),
            self.chain,
            addresses,
            as_of,
            self.limits.history_cap,
        )
        .await?;

        // Embedding is pure and microseconds-per-address, so it stays on the
        // reactor rather than paying a `spawn_blocking` hop: the page's cost
        // is its queries, not its arithmetic.
        let mut vectors = Vec::with_capacity(loaded.len() * self.versions.len());
        for address in addresses {
            if let Some((entity_id, inputs)) = loaded.get(address) {
                vectors.extend(self.embed_all(*address, *entity_id, inputs, as_of));
            }
        }

        let report = self.persist(&vectors, as_of, trigger).await?;
        metrics::histogram!(EMBEDDING_PAGE_DURATION).record(started.elapsed().as_secs_f64());
        Ok(report)
    }

    /// Apply [`decide_write`] across `vectors`, append the survivors in one
    /// batch, then publish them.
    ///
    /// Ordering is store-then-publish: the ClickHouse append is the durable
    /// fact, and an event announcing a vector no reader can find would be a
    /// lie a consumer cannot recover from (§7 — commit only after the durable
    /// downstream write).
    async fn persist(
        &self,
        vectors: &[BehaviorVector],
        now: DateTime<Utc>,
        trigger: Trigger,
    ) -> Result<ComputeReport, EmbeddingError> {
        let mut report = ComputeReport {
            computed: vectors.len(),
            ..Default::default()
        };
        if vectors.is_empty() {
            return Ok(report);
        }
        metrics::counter!(EMBEDDINGS_COMPUTED_TOTAL, "trigger" => trigger.as_str())
            .increment(vectors.len() as u64);

        // One batched previous-state read per version — the authoritative
        // comparison, rather than an in-process cache that would forget on
        // restart and re-write the whole keyspace after every deploy.
        let mut previous: HashMap<(&'static str, AccountAddress), StoredEmbedding> = HashMap::new();
        for embedder in &self.versions {
            let version = embedder.version();
            let addresses: Vec<AccountAddress> = vectors
                .iter()
                .filter(|vector| vector.embedding_version() == version)
                .map(|vector| vector.address)
                .collect();
            for (address, stored) in self
                .embeddings
                .latest_many(self.chain, &addresses, version)
                .await?
            {
                previous.insert((version, address), stored);
            }
        }

        let mut to_write = Vec::with_capacity(vectors.len());
        for vector in vectors {
            let decision = decide_write(
                previous.get(&(vector.embedding_version(), vector.address)),
                vector,
                self.limits.refresh_interval,
                now,
            );
            metrics::counter!(
                EMBEDDINGS_WRITTEN_TOTAL,
                "trigger" => trigger.as_str(),
                "reason" => decision.as_str(),
            )
            .increment(u64::from(decision.writes()));

            if decision.writes() {
                if vector.observations_truncated {
                    metrics::counter!(EMBEDDINGS_TRUNCATED_TOTAL).increment(1);
                }
                to_write.push(vector.clone());
            } else {
                report.skipped += 1;
            }
        }
        metrics::counter!(EMBEDDINGS_SKIPPED_TOTAL, "trigger" => trigger.as_str())
            .increment(report.skipped as u64);

        if to_write.is_empty() {
            return Ok(report);
        }
        self.embeddings.append(self.chain, &to_write).await?;
        report.written = to_write.len();

        for vector in &to_write {
            self.publish(DomainEvent::AddressEmbeddingUpdated(vector.to_event()))
                .await;
        }
        Ok(report)
    }

    async fn publish(&self, payload: DomainEvent) {
        publish_resilient(
            self.sink.as_ref(),
            EventEnvelope::new(self.chain, payload),
            self.publish_backoff,
            &self.shutdown,
        )
        .await;
    }

    /// Every *current* member of `entity_ids`, in encounter order, duplicates
    /// and all — [`compute`](Self::compute) is what deduplicates. A tombstoned
    /// or missing entity id (already superseded by a later merge/split)
    /// contributes nothing: whatever superseded it carries its own event.
    pub(crate) async fn addresses_for_entities(
        &self,
        entity_ids: &[EntityId],
    ) -> Result<Vec<AccountAddress>, EmbeddingError> {
        let entities = self.stores.entities.entities(entity_ids).await?;
        Ok(entity_ids
            .iter()
            .filter_map(|id| entities.get(id))
            .flat_map(|entity| entity.addresses.iter().copied())
            .collect())
    }

    pub(crate) fn shutdown(&self) -> &CancellationToken {
        &self.shutdown
    }

    /// One page of sweep candidates, on this instance's chain — the sweep's
    /// only reach into the graph, kept here so the sweep holds an
    /// [`Embedder`] rather than a second copy of its seams.
    pub(crate) async fn graph_active_addresses(
        &self,
        since: DateTime<Utc>,
        after: Option<AccountAddress>,
        limit: u32,
        shard: crate::adjacency::Shard,
    ) -> Result<Vec<AccountAddress>, EmbeddingError> {
        Ok(self
            .graph
            .active_addresses(self.chain, since, after, limit, shard)
            .await?)
    }
}

/// Test scaffolding shared with [`crate::embedding_sweep`] and
/// [`crate::embedding_consumer`]: they drive this same core, so their tests
/// build the same harness rather than each standing up a near-copy that could
/// drift from what production wires together.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::embedding::v1;
    use crate::model::{AdjacencyEdge, EdgeKind, LabelRecord, LabelSource, SanctionEntry};
    use crate::store::{LabelStore, SanctionsStore};
    use crate::test_util::{
        store_seams, InMemoryAdjacency, InMemoryIntelligenceStore, RecordingEmbeddingStore,
    };
    use alloy_primitives::Address;
    use event_bus::test_util::RecordingSink;
    use events::intelligence::AddressEmbeddingUpdated;
    use events::primitives::LabelKind;

    pub(crate) const CHAIN: Chain = Chain::ETHEREUM;
    const DAY: i64 = 86_400;

    pub(crate) fn addr(byte: u8) -> AccountAddress {
        Address::repeat_byte(byte)
    }

    pub(crate) fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(secs, 0).unwrap()
    }

    pub(crate) fn adjacency_edge(src: u8, dst: u8, at_secs: i64) -> AdjacencyEdge {
        AdjacencyEdge {
            chain: CHAIN,
            src: addr(src),
            dst: addr(dst),
            kind: EdgeKind::Interacted,
            evidence: format!("0x{at_secs:x}"),
            block_number: at_secs as u64,
            observed_at: at(at_secs),
        }
    }

    /// The `AddressEmbeddingUpdated`s among the recorded events — the same thin
    /// crate-local projection over the shared [`RecordingSink`] the risk-scorer
    /// tests use.
    pub(crate) trait EmbeddingsExt {
        fn embeddings(&self) -> Vec<AddressEmbeddingUpdated>;
    }

    impl EmbeddingsExt for RecordingSink {
        fn embeddings(&self) -> Vec<AddressEmbeddingUpdated> {
            self.events()
                .into_iter()
                .filter_map(|e| match e {
                    DomainEvent::AddressEmbeddingUpdated(update) => Some(update),
                    _ => None,
                })
                .collect()
        }
    }

    pub(crate) struct Harness {
        pub embedder: Embedder,
        pub sink: Arc<RecordingSink>,
        pub store: Arc<InMemoryIntelligenceStore>,
        pub graph: Arc<InMemoryAdjacency>,
        pub embeddings: Arc<RecordingEmbeddingStore>,
    }

    pub(crate) fn harness_with(limits: EmbeddingLimits) -> Harness {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let graph = Arc::new(InMemoryAdjacency::new());
        let embeddings = Arc::new(RecordingEmbeddingStore::new());
        let sink = Arc::new(RecordingSink::default());
        let embedder = Embedder::new(
            CHAIN,
            EmbedderSeams {
                stores: store_seams(&store),
                graph: graph.clone(),
                embeddings: embeddings.clone(),
                sink: sink.clone(),
            },
            CancellationToken::new(),
            limits,
            vec![],
        );
        Harness {
            embedder,
            sink,
            store,
            graph,
            embeddings,
        }
    }

    pub(crate) fn harness() -> Harness {
        harness_with(EmbeddingLimits::default())
    }

    fn stored(vector: &BehaviorVector, computed_at: DateTime<Utc>) -> StoredEmbedding {
        StoredEmbedding {
            address: vector.address,
            entity_id: vector.entity_id,
            embedding_version: vector.embedding_version().to_owned(),
            schema_hash: vector.schema_hash().to_owned(),
            values: vector.values.clone(),
            top_factors: vector.to_event().top_factors,
            observations_truncated: vector.observations_truncated,
            computed_at,
        }
    }

    // ── decide_write: the pure change-detection rule ─────────────────

    #[test]
    fn a_never_seen_address_is_always_written() {
        let h = harness();
        let vector = default_embedder().embed(addr(1), None, &BehaviorInputs::default(), at(0));
        assert_eq!(
            decide_write(None, &vector, h.embedder.limits().refresh_interval, at(0)),
            WriteDecision::New
        );
    }

    /// The whole point of change detection: a dormant address recomputed an
    /// hour later differs only in when it ran, and writing that forever is
    /// rows no consumer can act on.
    #[test]
    fn an_unchanged_vector_inside_the_refresh_window_is_skipped() {
        let vector = default_embedder().embed(addr(1), None, &BehaviorInputs::default(), at(3_600));
        let previous = stored(&vector, at(0));
        assert_eq!(
            decide_write(
                Some(&previous),
                &vector,
                Duration::from_secs(24 * 3_600),
                at(3_600)
            ),
            WriteDecision::Skip
        );
    }

    #[test]
    fn a_moved_value_is_written() {
        let vector = default_embedder().embed(addr(1), None, &BehaviorInputs::default(), at(0));
        let mut previous = stored(&vector, at(0));
        previous.values[0] = 0.5;
        assert_eq!(
            decide_write(Some(&previous), &vector, Duration::from_secs(9_999), at(0)),
            WriteDecision::Changed
        );
    }

    /// A frozen schema edited under a version that didn't move: the stored
    /// vector is in a different feature space, so leaving it would let a
    /// comparison silently mix the two.
    #[test]
    fn a_changed_schema_hash_is_always_rewritten() {
        let vector = default_embedder().embed(addr(1), None, &BehaviorInputs::default(), at(0));
        let mut previous = stored(&vector, at(0));
        previous.schema_hash = "a-different-schema".into();
        assert_eq!(
            decide_write(Some(&previous), &vector, Duration::from_secs(9_999), at(0)),
            WriteDecision::SchemaChanged
        );
    }

    /// Without the refresh floor, `computed_at` would say when the behavior
    /// last *changed*, with no way to tell that from "the job stopped running".
    #[test]
    fn an_unchanged_but_stale_vector_is_refreshed() {
        let vector = default_embedder().embed(addr(1), None, &BehaviorInputs::default(), at(DAY));
        let previous = stored(&vector, at(0));
        assert_eq!(
            decide_write(
                Some(&previous),
                &vector,
                Duration::from_secs(3_600),
                at(DAY)
            ),
            WriteDecision::Refresh
        );
    }

    /// A stored vector stamped ahead of `now` (clock skew, or a replay running
    /// behind live) is not stale — treating it as such would rewrite the row on
    /// every single pass.
    #[test]
    fn a_future_dated_stored_vector_is_not_treated_as_stale() {
        let vector = default_embedder().embed(addr(1), None, &BehaviorInputs::default(), at(0));
        let previous = stored(&vector, at(DAY));
        assert_eq!(
            decide_write(Some(&previous), &vector, Duration::from_secs(60), at(0)),
            WriteDecision::Skip
        );
    }

    // ── The compute core ─────────────────────────────────────────────

    #[tokio::test]
    async fn computing_an_address_stores_and_publishes_it_once() {
        let h = harness();
        h.graph
            .append(&[adjacency_edge(1, 2, 0), adjacency_edge(3, 1, DAY)])
            .await
            .unwrap();

        let report = h
            .embedder
            .compute(&[addr(1)], at(2 * DAY), Trigger::Manual)
            .await
            .unwrap();

        assert_eq!(report.computed, 1);
        assert_eq!(report.written, 1);
        assert_eq!(report.skipped, 0);

        let published = h.sink.embeddings();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].address, addr(1));
        assert_eq!(published[0].embedding_version, v1::VERSION);
        assert_eq!(published[0].vector.len(), v1::SCHEMA.dimension());
        assert_eq!(h.embeddings.appended().len(), 1);
    }

    /// The second identical pass writes and publishes *nothing* — the whole
    /// reason change detection exists.
    #[tokio::test]
    async fn an_unchanged_recompute_is_neither_stored_nor_published() {
        let h = harness();
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();

        h.embedder
            .compute(&[addr(1)], at(DAY), Trigger::Sweep)
            .await
            .unwrap();
        let report = h
            .embedder
            .compute(&[addr(1)], at(DAY), Trigger::Sweep)
            .await
            .unwrap();

        assert_eq!(report.computed, 1);
        assert_eq!(report.written, 0);
        assert_eq!(report.skipped, 1);
        assert_eq!(h.sink.embeddings().len(), 1, "published once, not twice");
        assert_eq!(h.embeddings.appended().len(), 1);
    }

    #[tokio::test]
    async fn a_changed_input_is_stored_and_published_again() {
        let h = harness();
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();
        h.embedder
            .compute(&[addr(1)], at(DAY), Trigger::Sweep)
            .await
            .unwrap();

        // A new observation moves the cadence and counterparty families.
        h.graph
            .append(&[adjacency_edge(1, 9, DAY / 2)])
            .await
            .unwrap();
        let report = h
            .embedder
            .compute(&[addr(1)], at(DAY), Trigger::Sweep)
            .await
            .unwrap();

        assert_eq!(report.written, 1);
        let published = h.sink.embeddings();
        assert_eq!(published.len(), 2);
        assert_ne!(published[0].vector, published[1].vector);
    }

    #[tokio::test]
    async fn a_stale_but_unchanged_vector_is_refreshed_on_the_next_pass() {
        let h = harness_with(EmbeddingLimits {
            refresh_interval: Duration::from_secs(60),
            ..Default::default()
        });
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();

        h.embedder
            .compute(&[addr(1)], at(DAY), Trigger::Sweep)
            .await
            .unwrap();
        let report = h
            .embedder
            .compute(&[addr(1)], at(DAY + 3_600), Trigger::Sweep)
            .await
            .unwrap();

        assert_eq!(report.written, 1, "the refresh floor forces a rewrite");
        assert_eq!(h.embeddings.appended().len(), 2);
    }

    #[tokio::test]
    async fn addresses_are_deduplicated_before_computing() {
        let h = harness();
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();
        let report = h
            .embedder
            .compute(&[addr(1), addr(1), addr(1)], at(DAY), Trigger::Manual)
            .await
            .unwrap();
        assert_eq!(report.computed, 1);
    }

    /// The batched load must produce exactly what the single-address load
    /// does — they are the same function, and this is the test that keeps the
    /// page path honest as it grows.
    #[tokio::test]
    async fn a_page_load_matches_a_single_load_address_for_address() {
        let h = harness();
        h.graph
            .append(&[
                adjacency_edge(1, 2, 0),
                adjacency_edge(3, 1, DAY),
                adjacency_edge(2, 3, 2 * DAY),
            ])
            .await
            .unwrap();
        h.store
            .add_label(&LabelRecord::new(
                addr(2),
                LabelKind::CexWallet,
                "cex",
                LabelSource::ExternalFeed,
                "test",
                at(0),
            ))
            .await
            .unwrap();

        let stores = store_seams(&h.store);
        let page = load_behavior_inputs_many(
            &stores,
            h.graph.as_ref(),
            CHAIN,
            &[addr(1), addr(2), addr(3)],
            at(3 * DAY),
            512,
        )
        .await
        .unwrap();

        for address in [addr(1), addr(2), addr(3)] {
            let (single_entity, single) =
                load_behavior_inputs(&stores, h.graph.as_ref(), CHAIN, &address, at(3 * DAY), 512)
                    .await
                    .unwrap();
            let (page_entity, page_inputs) = page.get(&address).expect("one entry per address");

            assert_eq!(*page_entity, single_entity);
            assert_eq!(page_inputs.history, single.history);
            assert_eq!(page_inputs.counterparty_labels, single.counterparty_labels);
            assert_eq!(page_inputs.labels, single.labels);
            assert_eq!(page_inputs.sanctions, single.sanctions);
            assert_eq!(page_inputs.entity, single.entity);

            // …and therefore the same vector.
            let from_page =
                default_embedder().embed(address, *page_entity, page_inputs, at(3 * DAY));
            let from_single =
                default_embedder().embed(address, single_entity, &single, at(3 * DAY));
            assert_eq!(from_page.values, from_single.values);
        }
    }

    /// A page splits into batches, and every address is still computed exactly
    /// once — the bound is on concurrency, not on coverage.
    #[tokio::test]
    async fn a_page_larger_than_the_batch_size_still_covers_every_address() {
        let h = harness_with(EmbeddingLimits {
            batch_size: 2,
            ..Default::default()
        });
        let addresses: Vec<AccountAddress> = (1..=7).map(addr).collect();
        let edges: Vec<AdjacencyEdge> = (1..=7).map(|n| adjacency_edge(n, 0xFF, 0)).collect();
        h.graph.append(&edges).await.unwrap();

        let report = h
            .embedder
            .compute(&addresses, at(DAY), Trigger::Sweep)
            .await
            .unwrap();

        assert_eq!(report.computed, 7);
        let mut seen: Vec<AccountAddress> =
            h.sink.embeddings().into_iter().map(|e| e.address).collect();
        seen.sort();
        assert_eq!(seen, addresses);
    }

    /// The subject's own labels and its counterparties' labels are different
    /// feature families — an address that funded itself must not count as its
    /// own counterparty.
    #[tokio::test]
    async fn loading_inputs_separates_own_labels_from_counterparty_labels() {
        let h = harness();
        h.graph
            .append(&[adjacency_edge(1, 2, 0), adjacency_edge(1, 1, DAY)])
            .await
            .unwrap();
        h.store
            .add_label(&LabelRecord::new(
                addr(1),
                LabelKind::MevBot,
                "self",
                LabelSource::Heuristic,
                "test",
                at(0),
            ))
            .await
            .unwrap();
        h.store
            .add_label(&LabelRecord::new(
                addr(2),
                LabelKind::CexWallet,
                "counterparty",
                LabelSource::ExternalFeed,
                "test",
                at(0),
            ))
            .await
            .unwrap();

        let (_, inputs) = load_behavior_inputs(
            &store_seams(&h.store),
            h.graph.as_ref(),
            CHAIN,
            &addr(1),
            at(2 * DAY),
            512,
        )
        .await
        .unwrap();

        assert_eq!(inputs.labels.len(), 1, "its own label");
        assert_eq!(
            inputs.counterparty_labels.keys().collect::<Vec<_>>(),
            vec![&addr(2)],
            "the self-edge is not a counterparty"
        );
    }

    #[tokio::test]
    async fn sanctions_and_entity_membership_reach_the_vector() {
        let h = harness();
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();
        h.store
            .seed_sanctions(&[SanctionEntry {
                address: addr(1),
                list_name: "ofac_sdn".into(),
                entry: "Evil Corp".into(),
                listed_at: None,
            }])
            .await
            .unwrap();

        let vectors = h
            .embedder
            .compute_one(addr(1), at(DAY), Trigger::Manual)
            .await
            .unwrap();

        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].get("is_sanctioned"), Some(1.0));
        assert_eq!(
            vectors[0].get("counterparty_count_log"),
            Some(libm::log10(2.0) as f32)
        );
    }

    /// A hub's history is capped, and the vector says so — both in the flag
    /// the event carries and as a dimension of the vector itself.
    #[tokio::test]
    async fn a_hub_history_is_capped_and_marked() {
        let h = harness_with(EmbeddingLimits {
            history_cap: 2,
            ..Default::default()
        });
        let edges: Vec<AdjacencyEdge> = (0..5)
            .map(|i| adjacency_edge(1, 0xA0 + i, i as i64 * 60))
            .collect();
        h.graph.append(&edges).await.unwrap();

        let vectors = h
            .embedder
            .compute_one(addr(1), at(DAY), Trigger::Manual)
            .await
            .unwrap();

        assert!(vectors[0].observations_truncated);
        assert_eq!(vectors[0].get("is_hub"), Some(1.0));
        assert!(h.sink.embeddings()[0].observations_truncated);
    }

    /// A transient store fault must surface so the caller (the consumer) can
    /// leave the Kafka offset uncommitted — the recompute is idempotent, so a
    /// retry converges.
    #[tokio::test]
    async fn a_transient_append_failure_surfaces_and_publishes_nothing() {
        let h = harness();
        h.graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();
        h.embeddings.fail_next();

        let err = h
            .embedder
            .compute(&[addr(1)], at(DAY), Trigger::Event)
            .await
            .expect_err("the injected fault surfaces");

        assert!(err.is_transient());
        assert!(
            h.sink.embeddings().is_empty(),
            "nothing is published when the durable write failed"
        );
    }

    // ── The version registry, end to end ─────────────────────────────

    /// A rollout stores both versions for the same address, side by side —
    /// which is what makes shadowing a v2 possible without a flag day.
    #[tokio::test]
    async fn every_enabled_version_is_computed_and_stored_side_by_side() {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let graph = Arc::new(InMemoryAdjacency::new());
        let embeddings = Arc::new(RecordingEmbeddingStore::new());
        let sink = Arc::new(RecordingSink::default());
        // The roster ships one version today, so "both enabled versions" is
        // v1 named twice — enough to prove the *plumbing* fans out per version
        // and keys previous-state per version, which is what a real v2 needs.
        let embedder = Embedder::new(
            CHAIN,
            EmbedderSeams {
                stores: store_seams(&store),
                graph: graph.clone(),
                embeddings: embeddings.clone(),
                sink: sink.clone(),
            },
            CancellationToken::new(),
            EmbeddingLimits::default(),
            vec![default_embedder(), default_embedder()],
        );
        graph.append(&[adjacency_edge(1, 2, 0)]).await.unwrap();

        let report = embedder
            .compute(&[addr(1)], at(DAY), Trigger::Manual)
            .await
            .unwrap();
        assert_eq!(report.computed, 2, "one vector per enabled version");
    }

    #[test]
    fn an_empty_version_list_falls_back_to_the_default_embedder() {
        let h = harness();
        assert_eq!(h.embedder.versions().len(), 1);
        assert_eq!(h.embedder.versions()[0].version(), v1::VERSION);
    }
}
