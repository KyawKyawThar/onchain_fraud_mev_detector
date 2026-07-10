//! The enrichment seam (§9, Sprint 9 t4) — where the consumer fetches "what
//! intelligence currently says" about an event's subject address, scoped by
//! the compiled rule set's [`EnrichmentNeeds`] prefetch plan so the cost
//! scales with what the live rules actually test.
//!
//! [`EnrichmentSource`] is the boundary the consumer is written (and tested)
//! against; [`IntelligenceEnrichment`] is the production adapter over the
//! intelligence crate's own store/cache seams — the same `labels_for` /
//! `sanction_matches` / cache-aside-risk reads intelligence's `IntelligenceRead`
//! gRPC service serves, so the two views can't drift. If this service is ever
//! deployed against a *remote* intelligence (rather than the shared Postgres/
//! Redis of §14's single deployment), the swap is a second adapter behind this
//! same trait — the consumer doesn't change.
//!
//! ## Honest gaps (documented, not silent)
//!
//! Two [`Enrichment`] fields have no production read path yet and stay empty:
//!
//! * `hop_distance` — needs a bounded BFS over the §8.2 adjacency graph from
//!   each rule anchor; the ClickHouse read exists (`clustering_neighbors`) but
//!   a per-event walk is a latency decision to make deliberately, not slip in.
//! * `first_active_block` — first-activity is not recorded anywhere yet (it is
//!   a chain-history projection, not an intelligence fact).
//!
//! Until those land, `HopDistance`/`NewAddress` conditions compile and store
//! fine but never match in production — the same stance as simulation's
//! documented resolver stub: the plumbing is honest about what it can answer.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use events::primitives::{AccountAddress, EntityId};
use intelligence::cache::{CachedScore, HotCache};
use intelligence::risk::{self, MODEL_VERSION};
use intelligence::risk_scorer::load_risk_inputs;
use intelligence::store::StoreSeams;

use crate::compile::EnrichmentNeeds;
use crate::ctx::Enrichment;

/// A failure fetching an enrichment snapshot. Transport-agnostic (a message +
/// the retry/skip decision, like `event-bus::PublishError`) so the
/// [`EnrichmentSource`] seam doesn't leak any one backend's error type into
/// the consumer.
#[derive(Debug, thiserror::Error)]
#[error("enrichment fetch failed: {message}")]
pub struct EnrichError {
    pub message: String,
    transient: bool,
}

impl EnrichError {
    /// A fault that could succeed on retry (store/cache blip).
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            transient: true,
        }
    }

    /// A fault that fails identically on every retry (a malformed row).
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            transient: false,
        }
    }

    /// Whether retrying the same fetch could plausibly succeed — what the
    /// consumer maps onto the shared retry/skip offset decision (§4).
    pub fn is_transient(&self) -> bool {
        self.transient
    }
}

/// Where the consumer reads the current intelligence state from (§9: state
/// predicates test *what is currently true*, never an event-payload copy).
#[async_trait]
pub trait EnrichmentSource: Send + Sync {
    /// Snapshot what intelligence currently says about `address`, fetching
    /// only what `needs` says some enabled rule tests. `counterparty` is the
    /// other party of a transfer event, when there is one (feeds
    /// `Enrichment::counterparty_labels`); `as_of` is the event's time, so
    /// label reads are replay-deterministic (§18).
    async fn enrichment(
        &self,
        address: &AccountAddress,
        counterparty: Option<&AccountAddress>,
        needs: &EnrichmentNeeds,
        as_of: DateTime<Utc>,
    ) -> Result<Enrichment, EnrichError>;

    /// Current member addresses of an entity — the fan-out for `EntityMerged`
    /// (a merge changes the state of *every* member, so each is re-evaluated).
    async fn entity_members(&self, entity_id: EntityId)
        -> Result<Vec<AccountAddress>, EnrichError>;
}

/// The production [`EnrichmentSource`]: the intelligence stores + hot cache,
/// read exactly the way intelligence's own gRPC read service reads them
/// (cache-aside risk with best-effort repopulation, `labels_for` with an
/// explicit `as_of`).
pub struct IntelligenceEnrichment {
    stores: StoreSeams,
    cache: Arc<dyn HotCache>,
}

impl IntelligenceEnrichment {
    pub fn new(stores: StoreSeams, cache: Arc<dyn HotCache>) -> Self {
        Self { stores, cache }
    }

    /// The current risk score: hot cache first, live compute (and best-effort
    /// cache repopulation) on a miss — byte-for-byte the policy of
    /// `intelligence::grpc::get_risk_score`, so a rule and a screening call
    /// can never disagree about an address's score.
    async fn risk_score(
        &self,
        address: &AccountAddress,
        as_of: DateTime<Utc>,
    ) -> Result<u8, EnrichError> {
        if let Ok(Some(cached)) = self.cache.score(address, MODEL_VERSION).await {
            return Ok(cached.score);
        }

        let (entity_id, inputs) = load_risk_inputs(&self.stores, address, as_of)
            .await
            .map_err(store_err)?;
        let result = risk::score(*address, entity_id, &inputs, as_of);

        if let Err(err) = self
            .cache
            .put_score(
                address,
                &CachedScore {
                    score: result.score,
                    confidence: result.confidence,
                    model_version: result.model_version.clone(),
                    computed_at: as_of,
                },
            )
            .await
        {
            tracing::warn!(error = %err, "failed to repopulate the risk-score cache");
        }
        Ok(result.score)
    }
}

/// Map an intelligence store fault onto the seam's transport-agnostic error,
/// preserving the retry/skip classification.
fn store_err(err: intelligence::store::StoreError) -> EnrichError {
    if err.is_transient() {
        EnrichError::transient(err.to_string())
    } else {
        EnrichError::permanent(err.to_string())
    }
}

#[async_trait]
impl EnrichmentSource for IntelligenceEnrichment {
    async fn enrichment(
        &self,
        address: &AccountAddress,
        counterparty: Option<&AccountAddress>,
        needs: &EnrichmentNeeds,
        as_of: DateTime<Utc>,
    ) -> Result<Enrichment, EnrichError> {
        let mut enrichment = Enrichment::default();

        if needs.risk_score {
            enrichment.risk_score = Some(self.risk_score(address, as_of).await?);
        }

        if needs.entity_labels {
            // The address's own active labels. Labels of *other* members of
            // its entity are not unioned in per event — the §8.1 association
            // flywheel already propagates bad-actor labels across an entity's
            // members as stored rows, which is the durable (and auditable)
            // version of that union.
            enrichment.entity_labels = self
                .stores
                .labels
                .labels_for(address, as_of)
                .await
                .map_err(store_err)?
                .into_iter()
                .map(|label| (label.kind, label.confidence))
                .collect();
        }

        if needs.sanctions {
            enrichment.sanction_lists = self
                .stores
                .sanctions
                .sanction_matches(address)
                .await
                .map_err(store_err)?
                .into_iter()
                .map(|entry| entry.list_name)
                .collect();
        }

        if needs.counterparty_labels {
            if let Some(counterparty) = counterparty {
                enrichment.counterparty_labels = self
                    .stores
                    .labels
                    .labels_for(counterparty, as_of)
                    .await
                    .map_err(store_err)?
                    .into_iter()
                    .map(|label| label.kind)
                    .collect();
            }
        }

        // `hop_distance` and `first_active_block` stay empty — see the module
        // docs' honest-gaps note. The matchers treat absent as "no match", so
        // the gap is conservative (no false fires), never a panic.

        Ok(enrichment)
    }

    async fn entity_members(
        &self,
        entity_id: EntityId,
    ) -> Result<Vec<AccountAddress>, EnrichError> {
        Ok(self
            .stores
            .entities
            .entity(entity_id)
            .await
            .map_err(store_err)?
            .map(|entity| entity.addresses)
            .unwrap_or_default())
    }
}
