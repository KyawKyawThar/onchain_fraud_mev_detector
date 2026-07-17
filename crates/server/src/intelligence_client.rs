//! Thin gRPC client wrapper around intelligence's `IntelligenceRead` service
//! (§11) — reuses the generated `pb` client stub straight from that crate
//! rather than recompiling the proto here, so the wire contract can never
//! drift between the two.

use events::primitives::AccountAddress;
use intelligence::model::address_key;
use intelligence::pb::intelligence_read_client::IntelligenceReadClient;
use intelligence::pb::{
    BuilderLeaderboardReply, BuilderLeaderboardRequest, EntityGraphReply, EntityGraphRequest,
    EntityTimelineReply, EntityTimelineRequest, Label, LabelsRequest, RiskScoreReply,
    RiskScoreRequest,
};
use tonic::transport::Channel;
use tonic::Status;

#[derive(Clone)]
pub struct IntelligenceClient {
    inner: IntelligenceReadClient<Channel>,
}

impl IntelligenceClient {
    /// Connect to `addr` (`http://host:port`). Lazy — tonic's `Channel::connect`
    /// resolves and dials on first RPC, same "fails at first use" trade-off the
    /// rest of this service's outbound clients make.
    pub fn connect_lazy(addr: String) -> anyhow::Result<Self> {
        let channel = Channel::from_shared(addr)?.connect_lazy();
        Ok(Self {
            inner: IntelligenceReadClient::new(channel),
        })
    }

    pub async fn risk_score(&self, address: AccountAddress) -> Result<RiskScoreReply, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_risk_score(RiskScoreRequest {
                address: address_key(&address),
            })
            .await?;
        Ok(response.into_inner())
    }

    pub async fn labels(&self, address: AccountAddress) -> Result<Vec<Label>, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_labels(LabelsRequest {
                address: address_key(&address),
            })
            .await?;
        Ok(response.into_inner().labels)
    }

    /// The §10 builder/relay leaderboard: top builders by sandwich volume and
    /// per-relay market share by MEV type.
    pub async fn builder_leaderboard(
        &self,
        chain: u64,
        limit: u32,
        since_unix_millis: Option<i64>,
    ) -> Result<BuilderLeaderboardReply, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_builder_leaderboard(BuilderLeaderboardRequest {
                chain,
                limit,
                since_unix_millis,
            })
            .await?;
        Ok(response.into_inner())
    }

    /// The entity's degree-capped connected-address subgraph (§8.2/§11), out to
    /// `hops` levels (`0` = server default).
    pub async fn entity_graph(
        &self,
        entity_id: String,
        chain: u64,
        hops: u32,
    ) -> Result<EntityGraphReply, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_entity_graph(EntityGraphRequest {
                entity_id,
                chain,
                hops,
            })
            .await?;
        Ok(response.into_inner())
    }

    /// The entity's curated milestone timeline (§8.4/§11).
    pub async fn entity_timeline(&self, entity_id: String) -> Result<EntityTimelineReply, Status> {
        let mut client = self.inner.clone();
        let response = client
            .get_entity_timeline(EntityTimelineRequest { entity_id })
            .await?;
        Ok(response.into_inner())
    }
}
