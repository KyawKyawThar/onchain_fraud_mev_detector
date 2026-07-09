//! The `IntelligenceRead` gRPC service (§11): the two synchronous-screening
//! lookups a caller reaches in-network — an address's current risk score and
//! its active labels.
//!
//! Cache-aside over the exact seams already built for this: a
//! [`HotCache`] hit answers immediately; a miss computes live via the same
//! path the `score` consumer and `intelligence risk` CLI subcommand use
//! ([`risk_scorer::load_risk_inputs`] → [`risk::score`], or
//! [`LabelStore::labels_for`]) and repopulates the cache for next time. A
//! cache *fault* (as opposed to a clean miss) is treated the same as a miss —
//! [`cache`]'s rule that the cache is "an optimization, never the record"
//! applies here too, so a Redis blip degrades this RPC's latency, not its
//! correctness.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use events::primitives::AccountAddress;
use tonic::{Request, Response, Status};

use crate::cache::{CachedScore, HotCache};
use crate::model::{self, LabelRecord};
use crate::pb::intelligence_read_server::IntelligenceRead;
use crate::pb::{Label, LabelsReply, LabelsRequest, RiskScoreReply, RiskScoreRequest};
use crate::risk::{self, MODEL_VERSION};
use crate::risk_scorer;
use crate::store::StoreSeams;

/// The service implementation. Cheap to clone — every field is `Arc`-backed —
/// which is what tonic requires to hand the service to each connection.
#[derive(Clone)]
pub struct IntelligenceReadService {
    stores: StoreSeams,
    cache: Arc<dyn HotCache>,
}

impl IntelligenceReadService {
    pub fn new(stores: StoreSeams, cache: Arc<dyn HotCache>) -> Self {
        Self { stores, cache }
    }
}

/// Parse the wire address via the crate's canonical [`model::parse_address_key`]
/// (the same mapping Postgres rows/Redis keys/ClickHouse columns use), mapping
/// a bad value to `INVALID_ARGUMENT` rather than the `INTERNAL` a store/cache
/// failure gets.
fn parse_address(raw: &str) -> Result<AccountAddress, Status> {
    model::parse_address_key(raw).map_err(|err| Status::invalid_argument(err.to_string()))
}

fn millis(at: DateTime<Utc>) -> i64 {
    at.timestamp_millis()
}

fn to_pb_label(label: &LabelRecord) -> Label {
    Label {
        label_id: label.label_id.to_string(),
        kind: <&'static str>::from(label.kind).to_owned(),
        value: label.value.clone(),
        confidence: label.confidence.get(),
        source: <&'static str>::from(label.source).to_owned(),
        source_detail: label.source_detail.clone(),
        created_at_unix_millis: millis(label.created_at),
        valid_until_unix_millis: label.valid_until.map(millis),
    }
}

#[tonic::async_trait]
impl IntelligenceRead for IntelligenceReadService {
    async fn get_risk_score(
        &self,
        request: Request<RiskScoreRequest>,
    ) -> Result<Response<RiskScoreReply>, Status> {
        let address = parse_address(&request.into_inner().address)?;

        if let Ok(Some(cached)) = self.cache.score(&address, MODEL_VERSION).await {
            return Ok(Response::new(RiskScoreReply {
                score: u32::from(cached.score),
                confidence: cached.confidence.get(),
                model_version: cached.model_version,
                computed_at_unix_millis: millis(cached.computed_at),
            }));
        }

        let as_of = Utc::now();
        let (entity_id, inputs) = risk_scorer::load_risk_inputs(&self.stores, &address, as_of)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let result = risk::score(address, entity_id, &inputs, as_of);

        // Best-effort repopulate — a failed cache write never fails the read,
        // but it's worth knowing about (an ops-visible Redis blip), not silent.
        if let Err(err) = self
            .cache
            .put_score(
                &address,
                &CachedScore {
                    score: result.score,
                    confidence: result.confidence,
                    model_version: result.model_version.clone(),
                    computed_at: as_of,
                },
            )
            .await
        {
            tracing::warn!(
                error = %err,
                address = %model::address_key(&address),
                "failed to populate the risk-score cache after a live compute"
            );
        }

        Ok(Response::new(RiskScoreReply {
            score: u32::from(result.score),
            confidence: result.confidence.get(),
            model_version: result.model_version,
            computed_at_unix_millis: millis(as_of),
        }))
    }

    async fn get_labels(
        &self,
        request: Request<LabelsRequest>,
    ) -> Result<Response<LabelsReply>, Status> {
        let address = parse_address(&request.into_inner().address)?;

        if let Ok(Some(cached)) = self.cache.labels(&address).await {
            return Ok(Response::new(LabelsReply {
                labels: cached.iter().map(to_pb_label).collect(),
            }));
        }

        let labels = self
            .stores
            .labels
            .labels_for(&address, Utc::now())
            .await
            .map_err(|err| Status::internal(err.to_string()))?;

        if let Err(err) = self.cache.put_labels(&address, &labels).await {
            tracing::warn!(
                error = %err,
                address = %model::address_key(&address),
                "failed to populate the labels cache after a live read"
            );
        }

        Ok(Response::new(LabelsReply {
            labels: labels.iter().map(to_pb_label).collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_primitives::Address;

    use super::*;
    use crate::cache::HotCache;
    use crate::model::{LabelKind, LabelRecord, LabelSource};
    use crate::store::LabelStore;
    use crate::test_util::{store_seams, InMemoryHotCache, InMemoryIntelligenceStore};

    fn service() -> (
        IntelligenceReadService,
        Arc<InMemoryIntelligenceStore>,
        Arc<InMemoryHotCache>,
    ) {
        let store = Arc::new(InMemoryIntelligenceStore::new());
        let cache = Arc::new(InMemoryHotCache::new());
        let service = IntelligenceReadService::new(store_seams(&store), cache.clone());
        (service, store, cache)
    }

    #[tokio::test]
    async fn risk_score_cache_hit_skips_the_store() {
        let (service, _store, cache) = service();
        let address = Address::repeat_byte(0xAB);
        let cached = CachedScore {
            score: 42,
            confidence: events::primitives::Confidence::new(0.9),
            model_version: MODEL_VERSION.to_owned(),
            computed_at: Utc::now(),
        };
        cache.put_score(&address, &cached).await.unwrap();

        let reply = service
            .get_risk_score(Request::new(RiskScoreRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(reply.score, 42);
        assert_eq!(reply.model_version, MODEL_VERSION);
    }

    #[tokio::test]
    async fn risk_score_cache_miss_computes_live_and_populates_cache() {
        let (service, _store, cache) = service();
        let address = Address::repeat_byte(0xCD);

        // No labels/sanctions/entity on record: the pure kernel's documented
        // "no evidence" answer is 0/100 at confidence 0.0.
        let reply = service
            .get_risk_score(Request::new(RiskScoreRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.score, 0);
        assert_eq!(reply.model_version, MODEL_VERSION);

        let cached = cache.score(&address, MODEL_VERSION).await.unwrap();
        assert!(cached.is_some(), "a cache miss should populate the cache");
    }

    #[tokio::test]
    async fn labels_cache_miss_reads_the_store_and_populates_cache() {
        let (service, store, cache) = service();
        let address = Address::repeat_byte(0xEF);
        let label = LabelRecord::new(
            address,
            LabelKind::MevBot,
            "known bot",
            LabelSource::Manual,
            "operator:test",
            Utc::now(),
        );
        store.add_label(&label).await.unwrap();

        let reply = service
            .get_labels(Request::new(LabelsRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(reply.labels.len(), 1);
        assert_eq!(reply.labels[0].value, "known bot");

        let cached = cache.labels(&address).await.unwrap();
        assert!(cached.is_some(), "a cache miss should populate the cache");
    }

    #[tokio::test]
    async fn labels_cache_hit_skips_the_store() {
        let (service, _store, cache) = service();
        let address = Address::repeat_byte(0x12);
        let label = LabelRecord::new(
            address,
            LabelKind::CexWallet,
            "cached label",
            LabelSource::Manual,
            "operator:test",
            Utc::now(),
        );
        cache.put_labels(&address, &[label]).await.unwrap();

        let reply = service
            .get_labels(Request::new(LabelsRequest {
                address: format!("{address:#x}"),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(reply.labels.len(), 1);
        assert_eq!(reply.labels[0].value, "cached label");
    }

    #[test]
    fn invalid_address_is_rejected() {
        assert!(parse_address("not-an-address").is_err());
    }
}
